//! Select a Windows App account only for an explicit Enter action.
use super::*;

struct ProfileRow<T> {
    email: String,
    label: String,
    controls: T,
}

struct RowControls {
    row: AxElement,
    email_text: AxElement,
}

fn profile_rows(sheet: &AxElement) -> Option<Vec<ProfileRow<RowControls>>> {
    let controls = sheet_controls(sheet)?;
    let mut scrolls = controls
        .iter()
        .filter(|node| role_matches(node, "AXScrollArea"));
    let rows = children(scrolls.next()?).ok()?;
    if scrolls.next().is_some() || rows.is_empty() || rows.len() > 64 {
        return None;
    }
    rows.into_iter()
        .map(|row| {
            let texts: Vec<_> = children(&row)
                .ok()?
                .into_iter()
                .filter(|node| role_matches(node, "AXStaticText"))
                .collect();
            let [name, email, organization] = texts.as_slice() else {
                return None;
            };
            let label = format!(
                "{} {}",
                name.string_attr(AX_VALUE)?,
                organization.string_attr(AX_VALUE)?
            );
            Some(ProfileRow {
                label,
                email: email.string_attr(AX_VALUE)?,
                controls: RowControls {
                    row,
                    email_text: email.clone(),
                },
            })
        })
        .collect()
}

fn unique<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let item = items.next()?;
    items.next().is_none().then_some(item)
}

fn target_profile<'a, T>(
    rows: &'a [ProfileRow<T>],
    active_label: &str,
    email: &str,
) -> Result<(&'a ProfileRow<T>, bool)> {
    ensure!(!email.trim().is_empty(), PROFILE_ERROR);
    let current =
        unique(rows.iter().filter(|row| row.label == active_label)).context(PROFILE_ERROR)?;
    let target = unique(
        rows.iter()
            .filter(|row| row.email.eq_ignore_ascii_case(email.trim())),
    )
    .context(
        "Choose an account that is listed exactly once in the Windows App account selector.",
    )?;
    ensure!(
        unique(rows.iter().filter(|r| r.label == target.label)).is_some(),
        PROFILE_ERROR
    );
    Ok((target, target.label == current.label))
}

fn inspect_selector<T>(
    app: &AxElement,
    center: &AxElement,
    inspect: impl FnOnce(&AxElement, &str) -> Result<T>,
) -> Result<T> {
    let (button, label) = profile_label(center)?;
    ensure!(
        app.bool_attr(AX_FRONTMOST) == Some(true)
            && app
                .element_attr("AXFocusedWindow")
                .is_some_and(|w| w.same_element(center))
            && children(center)?
                .iter()
                .all(|node| !role_matches(node, "AXSheet")),
        PROFILE_ERROR
    );
    // An AXPress can time out after Windows App accepts it. Observe the sheet once.
    button.perform_action(AX_PRESS);
    let (sheet, close) = wait_for(|| profile_selector(center))
        .context("Windows App did not display its account selector.")?;
    let result = inspect(&sheet, &label);
    if children(center)?.iter().any(|w| w.same_element(&sheet)) {
        close.perform_action(AX_PRESS);
        wait_for(|| {
            children(center)
                .ok()?
                .iter()
                .all(|w| !w.same_element(&sheet))
                .then_some(())
        })
        .context("Windows App did not finish closing its account selector.")?;
    }
    result
}

pub(super) fn verify_selected_owner(
    app: &AxElement,
    center: &AxElement,
    email: &str,
) -> Result<String> {
    inspect_selector(app, center, |sheet, active| {
        let rows = wait_for(|| profile_rows(sheet)).context(PROFILE_ERROR)?;
        let (_, selected) = target_profile(&rows, active, email)?;
        ensure!(
            selected,
            "The selected desktop could not be verified under this Windows App account."
        );
        Ok(active.to_owned())
    })
}

pub(super) fn prepare_enter_devices(app: &AxElement, email: &str) -> Result<(DeviceList, String)> {
    let center = devices_window(app)?;
    let (label, switched) = inspect_selector(app, &center, |sheet, active| {
        let rows = wait_for(|| profile_rows(sheet)).context(PROFILE_ERROR)?;
        let (target, selected) = target_profile(&rows, active, email)?;
        if !selected {
            let RowControls {
                row,
                email_text: text,
            } = &target.controls;
            connected::click_profile_email(app, &center, sheet, row, text, || {
                ensure!(profile_label(&center)?.1 == active, PROFILE_ERROR);
                let current = profile_rows(sheet).context(PROFILE_ERROR)?;
                let (fresh, selected) = target_profile(&current, active, email)?;
                ensure!(
                    !selected
                        && fresh.label == target.label
                        && fresh.controls.row.same_element(row)
                        && fresh.controls.email_text.same_element(text),
                    PROFILE_ERROR
                );
                Ok(())
            })?;
            // The selector can stay open while the Devices view switches account.
            // Some builds update the accessible toolbar only after dismissal.
            // Give AppKit time to consume the single click before closing it.
            let until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < until
                && app.bool_attr(AX_FRONTMOST) == Some(true)
                && profile_label(&center).is_ok_and(|(_, label)| label != target.label)
                && children(&center)?.iter().any(|w| w.same_element(sheet))
            {
                std::thread::sleep(Duration::from_millis(35));
            }
        }
        Ok((target.label.clone(), !selected))
    })?;
    if switched {
        // The selector already tied this unique toolbar label to the requested email.
        // Wait for Windows App to show that profile after dismissing the sheet.
        wait_for(|| {
            (app.bool_attr(AX_FRONTMOST) == Some(true)
                && app.element_attr("AXFocusedWindow")?.same_element(&center)
                && profile_label(&center).ok()?.1 == label)
                .then_some(())
        })
        .context(PROFILE_ERROR)?;
    }
    // Read the new account's cards after confirming it. The previous account
    // may legitimately have had an empty Devices view.
    let list = devices_from_window(app.clone(), center)?;
    list.ensure_profile(&label)?;
    Ok((list, label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(email: &str, label: &str) -> ProfileRow<()> {
        ProfileRow {
            email: email.to_owned(),
            label: label.to_owned(),
            controls: (),
        }
    }

    #[test]
    fn exact_unique_email_selects_one_account_and_preserves_current_when_already_selected() {
        let rows = [
            row("one@example.test", "One Work"),
            row("two@example.test", "Two Work"),
        ];
        assert!(
            target_profile(&rows, "One Work", "ONE@example.test")
                .unwrap()
                .1
        );
        let (target, selected) = target_profile(&rows, "One Work", "TWO@example.test").unwrap();
        assert!(!selected);
        assert_eq!(target.label, "Two Work");
        for wrong in ["", "two", "two@example.test.attacker"] {
            assert!(target_profile(&rows, "One Work", wrong).is_err());
        }
    }

    #[test]
    fn ambiguous_email_active_label_or_requested_label_cannot_switch() {
        for (other_email, other_label) in [
            ("TWO@example.test", "Other"),
            ("elsewhere@example.test", "Two Work"),
            ("third@example.test", "One Work"),
        ] {
            let rows = [
                row("one@example.test", "One Work"),
                row("two@example.test", "Two Work"),
                row(other_email, other_label),
            ];
            assert!(target_profile(&rows, "One Work", "two@example.test").is_err());
        }
    }
}
