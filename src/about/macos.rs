use super::{ContactLink, APP_NAME, AUTHOR, CONTACTS, HOMEPAGE, VERSION};
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Bool};
use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{
    NSAboutPanelOptionApplicationName, NSAboutPanelOptionApplicationVersion,
    NSAboutPanelOptionCredits, NSAboutPanelOptionVersion, NSApplication,
    NSAttributedStringAttachmentConveniences, NSColor, NSCompositingOperation, NSFont,
    NSFontAttributeName, NSForegroundColorAttributeName, NSImage, NSLinkAttributeName,
    NSMutableParagraphStyle, NSParagraphStyleAttributeName, NSRectFillUsingOperation,
    NSTextAlignment, NSTextAttachment, NSToolTipAttributeName, NSUnderlineStyleAttributeName,
};
use objc2_foundation::{
    NSArray, NSAttributedString, NSBundle, NSCalendar, NSCalendarIdentifierGregorian, NSData,
    NSDate, NSDateFormatter, NSDateFormatterStyle, NSDictionary, NSLocale,
    NSMutableAttributedString, NSNumber, NSPoint, NSRange, NSRect, NSSize, NSString, NSTimeZone,
    NSURL,
};

const CONTACT_ICON_SIZE: f64 = 14.0;
const CONTACT_ITEM_SPACING: f64 = 18.0;

pub(super) fn show() -> anyhow::Result<()> {
    let mtm = MainThreadMarker::new()
        .ok_or_else(|| anyhow::anyhow!("the About panel requires the macOS main thread"))?;
    let name = NSString::from_str(
        &bundle_string("CFBundleDisplayName")
            .or_else(|| bundle_string("CFBundleName"))
            .unwrap_or_else(|| APP_NAME.to_string()),
    );
    let version =
        bundle_string("CFBundleShortVersionString").unwrap_or_else(|| VERSION.to_string());
    let bundle_build = bundle_string("CFBundleVersion").unwrap_or_default();
    let timestamp_build = bundle_build.len() == 14
        && bundle_build
            .bytes()
            .all(|character| character.is_ascii_digit());
    let released = if timestamp_build {
        parse_date(&bundle_build, "yyyyMMddHHmmss")
    } else {
        bundle_string("WAALReleaseDate").and_then(|date| parse_date(&date, "yyyy-MM-dd"))
    };
    // Match Instance Control: show a distinct build, but hide timestamps and duplicates.
    let build = NSString::from_str(if timestamp_build || bundle_build == version {
        ""
    } else {
        &bundle_build
    });
    let version = NSString::from_str(&version);
    let credits = credits(released.as_deref())?;

    // SAFETY: Every standard About-panel key is paired with its documented value type.
    let options = unsafe {
        NSDictionary::<NSString, AnyObject>::from_slices(
            &[
                NSAboutPanelOptionApplicationName,
                NSAboutPanelOptionApplicationVersion,
                NSAboutPanelOptionVersion,
                NSAboutPanelOptionCredits,
            ],
            &[&name, &version, &build, &credits],
        )
    };
    let app = NSApplication::sharedApplication(mtm);
    // Keep the standard panel usable from an accessory/menu-bar application on macOS 11+.
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
    // SAFETY: The typed options above contain NSString and NSAttributedString values.
    unsafe { app.orderFrontStandardAboutPanelWithOptions(&options) };
    Ok(())
}

fn bundle_string(key: &str) -> Option<String> {
    let value = NSBundle::mainBundle().objectForInfoDictionaryKey(&NSString::from_str(key))?;
    let value = value.downcast_ref::<NSString>()?.to_string();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn date_formatter() -> Retained<NSDateFormatter> {
    let formatter = NSDateFormatter::new();
    // SAFETY: Foundation's Gregorian calendar identifier is a valid static NSString.
    let calendar = unsafe { NSCalendar::calendarWithIdentifier(NSCalendarIdentifierGregorian) };
    formatter.setCalendar(calendar.as_deref());
    formatter.setTimeZone(Some(&NSTimeZone::timeZoneForSecondsFromGMT(0)));
    formatter
}

fn parse_date(value: &str, format: &str) -> Option<Retained<NSDate>> {
    let formatter = date_formatter();
    let locale =
        NSLocale::initWithLocaleIdentifier(NSLocale::alloc(), &NSString::from_str("en_US_POSIX"));
    formatter.setLocale(Some(&locale));
    formatter.setDateFormat(Some(&NSString::from_str(format)));
    formatter.setLenient(false);
    let date = formatter.dateFromString(&NSString::from_str(value))?;
    // Reject invalid or partially parsed dates instead of displaying a normalized guess.
    (formatter.stringFromDate(&date).to_string() == value).then_some(date)
}

fn release_date_text(date: &NSDate) -> String {
    let formatter = date_formatter();
    formatter.setLocale(Some(&NSLocale::autoupdatingCurrentLocale()));
    formatter.setDateStyle(NSDateFormatterStyle::MediumStyle);
    formatter.setTimeStyle(NSDateFormatterStyle::NoStyle);
    format!("Released {}\n", formatter.stringFromDate(date))
}

fn credits(release_date: Option<&NSDate>) -> anyhow::Result<Retained<NSMutableAttributedString>> {
    let paragraph = NSMutableParagraphStyle::new();
    paragraph.setAlignment(NSTextAlignment::Center);
    let spacer_paragraph = NSMutableParagraphStyle::new();
    spacer_paragraph.setAlignment(NSTextAlignment::Center);
    spacer_paragraph.setMinimumLineHeight(6.0);
    spacer_paragraph.setMaximumLineHeight(6.0);
    let release_spacer_paragraph = NSMutableParagraphStyle::new();
    release_spacer_paragraph.setAlignment(NSTextAlignment::Center);
    release_spacer_paragraph.setMinimumLineHeight(15.0);
    release_spacer_paragraph.setMaximumLineHeight(15.0);
    let contact_paragraph = NSMutableParagraphStyle::new();
    contact_paragraph.setAlignment(NSTextAlignment::Center);
    contact_paragraph.setParagraphSpacingBefore(20.0);

    let font = NSFont::systemFontOfSize(NSFont::smallSystemFontSize());
    let spacer_font = NSFont::systemFontOfSize(1.0);
    let text_color = NSColor::labelColor();
    let link_color = NSColor::linkColor();
    let homepage = NSURL::URLWithString(&NSString::from_str(HOMEPAGE))
        .ok_or_else(|| anyhow::anyhow!("invalid About homepage URL"))?;
    let underline = NSNumber::new_i32(1);

    // SAFETY: AppKit text attributes use the matching native font/color/paragraph/URL types.
    let (base_attributes, spacer_attributes, release_spacer_attributes, author_attributes) = unsafe {
        (
            NSDictionary::<NSString, AnyObject>::from_slices(
                &[
                    NSFontAttributeName,
                    NSForegroundColorAttributeName,
                    NSParagraphStyleAttributeName,
                ],
                &[&font, &text_color, &paragraph],
            ),
            NSDictionary::<NSString, AnyObject>::from_slices(
                &[NSFontAttributeName, NSParagraphStyleAttributeName],
                &[&spacer_font, &spacer_paragraph],
            ),
            NSDictionary::<NSString, AnyObject>::from_slices(
                &[NSFontAttributeName, NSParagraphStyleAttributeName],
                &[&spacer_font, &release_spacer_paragraph],
            ),
            NSDictionary::<NSString, AnyObject>::from_slices(
                &[
                    NSFontAttributeName,
                    NSForegroundColorAttributeName,
                    NSLinkAttributeName,
                    NSParagraphStyleAttributeName,
                    NSUnderlineStyleAttributeName,
                ],
                &[&font, &link_color, &homepage, &paragraph, &underline],
            ),
        )
    };

    // SAFETY: The dictionaries were constructed with documented AppKit attribute types.
    let result = unsafe {
        NSMutableAttributedString::initWithString_attributes(
            NSMutableAttributedString::alloc(),
            &NSString::from_str("\n"),
            Some(&spacer_attributes),
        )
    };
    if let Some(date) = release_date {
        append_text(&result, &release_date_text(date), &base_attributes);
        append_text(&result, "\n", &release_spacer_attributes);
    }
    append_text(&result, "Author\n", &base_attributes);
    append_text(&result, AUTHOR, &author_attributes);
    append_text(&result, "\n", &base_attributes);
    for link in CONTACTS {
        let image = contact_image(link)?;
        let attachment = NSTextAttachment::new();
        attachment.setImage(Some(&image));
        attachment.setBounds(NSRect::new(
            NSPoint::new(0.0, -CONTACT_ICON_SIZE / 5.0),
            NSSize::new(CONTACT_ICON_SIZE + CONTACT_ITEM_SPACING, CONTACT_ICON_SIZE),
        ));
        let url = NSURL::URLWithString(&NSString::from_str(link.url))
            .ok_or_else(|| anyhow::anyhow!("invalid About contact URL"))?;
        let label = NSString::from_str(link.label);
        // AttributeScopes.AccessibilityAttributes.TextCustomAttribute.name in the Swift reference.
        let accessibility_key = NSString::from_str("AXCustom");
        let accessibility_text = NSArray::from_slice(&[&*label]);
        // SAFETY: The link URL, tooltip string and paragraph style are the documented types.
        let attributed_icon = unsafe {
            let attributes = NSDictionary::<NSString, AnyObject>::from_slices(
                &[
                    NSLinkAttributeName,
                    NSToolTipAttributeName,
                    NSParagraphStyleAttributeName,
                    &accessibility_key,
                ],
                &[&url, &label, &contact_paragraph, &accessibility_text],
            );
            let attributed_icon = NSMutableAttributedString::initWithAttributedString(
                NSMutableAttributedString::alloc(),
                &NSAttributedString::attributedStringWithAttachment(&attachment),
            );
            attributed_icon
                .addAttributes_range(&attributes, NSRange::new(0, attributed_icon.length()));
            attributed_icon
        };
        result.appendAttributedString(&attributed_icon);
    }
    Ok(result)
}

fn append_text(
    output: &NSMutableAttributedString,
    text: &str,
    attributes: &NSDictionary<NSString, AnyObject>,
) {
    // SAFETY: Callers provide dictionaries containing the documented AppKit attribute types.
    let text = unsafe {
        NSAttributedString::initWithString_attributes(
            NSAttributedString::alloc(),
            &NSString::from_str(text),
            Some(attributes),
        )
    };
    output.appendAttributedString(&text);
}

fn contact_image(link: &ContactLink) -> anyhow::Result<Retained<NSImage>> {
    let label = NSString::from_str(link.label);
    let source = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(link.icon_svg))
        .or_else(|| {
            NSImage::imageWithSystemSymbolName_accessibilityDescription(
                &NSString::from_str("link"),
                Some(&label),
            )
        })
        .ok_or_else(|| anyhow::anyhow!("could not load an About contact icon"))?;
    let draw = RcBlock::new(move |rect: NSRect| -> Bool {
        source.drawInRect_fromRect_operation_fraction(
            NSRect::new(
                NSPoint::new(CONTACT_ITEM_SPACING / 2.0, 0.0),
                NSSize::new(CONTACT_ICON_SIZE, CONTACT_ICON_SIZE),
            ),
            NSRect::ZERO,
            NSCompositingOperation::SourceOver,
            1.0,
        );
        // Resolve the dynamic label color at drawing time, including dark appearance.
        NSColor::labelColor().setFill();
        NSRectFillUsingOperation(rect, NSCompositingOperation::SourceIn);
        Bool::YES
    });
    let image = NSImage::imageWithSize_flipped_drawingHandler(
        NSSize::new(CONTACT_ICON_SIZE + CONTACT_ITEM_SPACING, CONTACT_ICON_SIZE),
        false,
        &draw,
    );
    image.setAccessibilityDescription(Some(&label));
    Ok(image)
}
