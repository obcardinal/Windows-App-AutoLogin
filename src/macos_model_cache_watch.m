// Observe Vision's per-application compiled models without opening their contents.
#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>
#include <stdatomic.h>
#include <sys/sysctl.h>

@interface WaalModelCacheWatch : NSObject {
@public
    NSURL *directory;
    NSSet<NSString *> *previousFiles;
    NSMutableSet<NSString *> *unreportedFiles;
    BOOL startedEmpty;
    FSEventStreamRef stream;
    dispatch_queue_t queue;
    atomic_bool loss;
}
@end
@implementation WaalModelCacheWatch
@end

// Model and architecture identifiers depend on the OS and the machine. Track
// the compiled files actually present, including partially evicted bundles.
static void reconcile(WaalModelCacheWatch *watch) {
    @autoreleasepool {
        BOOL initial = watch->previousFiles == nil;
        NSMutableSet *files = [NSMutableSet set];
        NSMutableSet *expected = initial ? [NSMutableSet set] : nil;
        NSArray *keys = @[NSURLIsDirectoryKey, NSURLIsRegularFileKey, NSURLIsSymbolicLinkKey];
        NSDirectoryEnumerator *entries = [NSFileManager.defaultManager
            enumeratorAtURL:watch->directory includingPropertiesForKeys:keys options:0 errorHandler:nil];
        for (NSURL *entry in entries) {
            NSDictionary *props = [entry resourceValuesForKeys:keys error:nil];
            NSString *name = entry.lastPathComponent;
            BOOL isDirectory = [props[NSURLIsDirectoryKey] boolValue];
            // Vision compiles in <model>.tmp.<pid>_<id>.bundle before moving
            // the finished bundle into place. Its removals are ordinary writes.
            BOOL staging = isDirectory && [entry.pathExtension isEqualToString:@"bundle"] &&
                           [name containsString:@".tmp."];
            if ([props[NSURLIsSymbolicLinkKey] boolValue] || staging) {
                [entries skipDescendants];
                continue;
            }
            if ([props[NSURLIsRegularFileKey] boolValue] &&
                    ([entry.pathExtension isEqualToString:@"e5"] || [name isEqualToString:@"model.anehash"])) {
                [files addObject:entry.path];
            } else if (initial && isDirectory) {
                if ([name isEqualToString:@"main_ane"]) {
                    [expected addObject:[entry.path stringByAppendingPathComponent:@"model.anehash"]];
                } else if ([entry.pathExtension isEqualToString:@"bundle"] &&
                           [entry.URLByDeletingLastPathComponent.pathExtension isEqualToString:@"bundle"]) {
                    NSString *compiled = [name.stringByDeletingPathExtension stringByAppendingPathExtension:@"e5"];
                    [expected addObject:[entry.path stringByAppendingPathComponent:compiled]];
                }
            }
        }
        NSMutableSet *disappeared = initial ? expected : watch->previousFiles.mutableCopy;
        [disappeared minusSet:files];
        [watch->unreportedFiles unionSet:disappeared];
        [watch->unreportedFiles minusSet:files];
        if (initial) watch->startedEmpty = files.count == 0;
        atomic_store(&watch->loss, watch->startedEmpty || watch->unreportedFiles.count != 0);
        watch->previousFiles = files;
    }
}

static void modelCacheChanged(ConstFSEventStreamRef stream, void *context, size_t count,
                              void *paths, const FSEventStreamEventFlags flags[],
                              const FSEventStreamEventId ids[]) {
    (void)stream; (void)count; (void)paths; (void)flags; (void)ids;
    // The stream watches only this model tree. Rescan once per delivered batch
    // so coalesced directory moves and dropped events use the same logic.
    reconcile((__bridge WaalModelCacheWatch *)context);
}

// The same path-based implementation is exercised against a disposable tree
// by the native integration test. The app always selects its own Vision cache.
void *waal_model_cache_watch_directory(const char *path) {
    @autoreleasepool {
        if (!path) return NULL;
        WaalModelCacheWatch *watch = [WaalModelCacheWatch new];
        watch->directory = [NSURL fileURLWithFileSystemRepresentation:path isDirectory:YES relativeToURL:nil];
        watch->unreportedFiles = [NSMutableSet set];
        atomic_init(&watch->loss, false);
        FSEventStreamContext context = {0, (__bridge void *)watch, CFRetain, CFRelease, NULL};
        FSEventStreamRef stream = FSEventStreamCreate(NULL, modelCacheChanged, &context,
            (__bridge CFArrayRef)@[watch->directory.path], kFSEventStreamEventIdSinceNow, 0.25,
            kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagFileEvents);
        if (!stream) return NULL;
        watch->stream = stream;
        watch->queue = dispatch_queue_create("com.obcardinal.autologin.vision-cache", DISPATCH_QUEUE_SERIAL);
        FSEventStreamSetDispatchQueue(stream, watch->queue);
        // Arm delivery before taking the baseline. Events during the scan are
        // reconciled on this queue after the baseline has been recorded.
        __block Boolean started;
        dispatch_sync(watch->queue, ^{
            started = FSEventStreamStart(stream);
            if (started) reconcile(watch);
        });
        if (!started) {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            return NULL;
        }
        return (__bridge_retained void *)watch;
    }
}

void *waal_model_cache_watch_start(void) {
    @autoreleasepool {
        NSURL *caches = [NSFileManager.defaultManager URLsForDirectory:NSCachesDirectory
                                                             inDomains:NSUserDomainMask].firstObject;
        NSString *owner = NSBundle.mainBundle.bundleIdentifier ?: NSProcessInfo.processInfo.processName;
        char build[256];
        size_t length = sizeof(build);
        if (!caches || !owner.length || sysctlbyname("kern.osversion", build, &length, NULL, 0) != 0)
            return NULL;
        NSURL *app = [caches URLByAppendingPathComponent:owner isDirectory:YES];
        NSURL *models = [app URLByAppendingPathComponent:@"com.apple.e5rt.e5bundlecache" isDirectory:YES];
        NSURL *current = [models URLByAppendingPathComponent:@(build) isDirectory:YES];
        return waal_model_cache_watch_directory(current.fileSystemRepresentation);
    }
}

bool waal_model_cache_watch_take_loss(void *handle) {
    WaalModelCacheWatch *watch = (__bridge WaalModelCacheWatch *)handle;
    if (!watch || !atomic_load(&watch->loss)) return false;
    // A purge may arrive in multiple batches while the previous repair is
    // compiling. Recheck these pending removals before starting another
    // repair, even if FSEvents hasn't delivered the final creations yet.
    __block bool needed;
    dispatch_sync(watch->queue, ^{
        reconcile(watch);
        needed = atomic_exchange(&watch->loss, false);
        watch->startedEmpty = NO;
        [watch->unreportedFiles removeAllObjects];
    });
    return needed;
}

void waal_model_cache_watch_stop(void *handle) {
    if (!handle) return;
    WaalModelCacheWatch *watch = (__bridge_transfer WaalModelCacheWatch *)handle;
    FSEventStreamStop(watch->stream);
    FSEventStreamInvalidate(watch->stream);
    FSEventStreamRelease(watch->stream);
}
