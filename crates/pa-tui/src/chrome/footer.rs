//! The footer status row under the tray: the `~`-compressed cwd and git
//! branch left, the session's token totals and latest cache hit rate right.

use std::path::Path;

use serde_json::Value;

use super::{format_splash_cwd, format_token_count};
use crate::theme::{Theme, ThemeColor};
use crate::width::{str_width, truncate_to_width};
use crate::{Line, Span};

/// The footer row's session data; the cwd comes from the chrome state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FooterStatus {
    /// The branch name, or the short commit id on a detached HEAD.
    pub branch: Option<String>,
    pub tokens: TokenTotals,
    /// Cache reads over the latest response's prompt tokens, in percent.
    pub cache_hit_percent: Option<f64>,
}

/// The session's token spend (`get_session_stats` `tokens`), including the
/// subagent usage attributed to its turns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenTotals {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl TokenTotals {
    pub(crate) fn from_stats(stats: &Value) -> Self {
        let field = |name: &str| {
            stats
                .get("tokens")
                .and_then(|tokens| tokens.get(name))
                .and_then(Value::as_u64)
                .unwrap_or_default()
        };
        Self {
            input: field("input"),
            output: field("output"),
            cache_read: field("cacheRead"),
            cache_write: field("cacheWrite"),
        }
    }
}

/// The cache hit rate of one assistant message's usage; `None` without
/// prompt tokens.
pub(crate) fn cache_hit_percent(message: &Value) -> Option<f64> {
    let usage = message.get("usage")?;
    let field = |name: &str| usage.get(name).and_then(Value::as_u64).unwrap_or_default();
    let cache_read = field("cacheRead");
    let prompt = field("input") + cache_read + field("cacheWrite");
    (prompt > 0).then(|| cache_read as f64 / prompt as f64 * 100.0)
}

/// The checked-out branch of the repository containing `cwd`, read from
/// `HEAD` without running git. A `.git` file (worktree, submodule) points
/// at the real git dir.
pub(crate) fn read_git_branch(cwd: &Path) -> Option<String> {
    // An unset cwd would otherwise resolve `.git` against the process cwd.
    if cwd.as_os_str().is_empty() {
        return None;
    }
    let dot_git = cwd
        .ancestors()
        .map(|dir| dir.join(".git"))
        .find(|path| path.exists())?;
    let git_dir = if dot_git.is_file() {
        let pointer = std::fs::read_to_string(&dot_git).ok()?;
        let target = pointer.trim().strip_prefix("gitdir:")?.trim();
        dot_git.parent()?.join(target)
    } else {
        dot_git
    };
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    match head.strip_prefix("ref: ") {
        Some(reference) => Some(
            reference
                .strip_prefix("refs/heads/")
                .unwrap_or(reference)
                .to_string(),
        ),
        None => Some(head.chars().take(7).collect()),
    }
}

/// The footer row; `None` when there is nothing to show. A row wider than
/// `width` is cut from the right.
pub(crate) fn render_footer_status(
    cwd: &str,
    status: &FooterStatus,
    theme: &Theme,
    width: usize,
) -> Option<Line> {
    let home = pa_types::platform::home_dir().map(|home| home.to_string_lossy().into_owned());
    let mut left = if cwd.is_empty() {
        String::new()
    } else {
        format_splash_cwd(cwd, home.as_deref())
    };
    if let Some(branch) = &status.branch {
        left = format!("{left} ({branch})").trim_start().to_string();
    }
    let tokens = status.tokens;
    let mut parts = Vec::new();
    for (prefix, count) in [
        ("\u{2191}", tokens.input),
        ("\u{2193}", tokens.output),
        ("R", tokens.cache_read),
        ("W", tokens.cache_write),
    ] {
        if count > 0 {
            parts.push(format!("{prefix}{}", format_token_count(count)));
        }
    }
    if tokens.cache_read > 0 || tokens.cache_write > 0 {
        if let Some(percent) = status.cache_hit_percent {
            parts.push(format!("CH{percent:.1}%"));
        }
    }
    let right = parts.join(" ");
    if left.is_empty() && right.is_empty() {
        return None;
    }
    let gap = width
        .saturating_sub(str_width(&left) + str_width(&right))
        .max(2);
    let row = truncate_to_width(
        &format!("{left}{}{right}", " ".repeat(gap)),
        width,
        "\u{2026}",
    );
    Some(vec![Span::styled(row, theme.fg_style(ThemeColor::Dim))])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line) -> String {
        line.iter().map(|span| span.content.as_str()).collect()
    }

    #[test]
    fn footer_row_reads_the_branch_and_lays_out_location_and_tokens() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::write(
            repo.path().join(".git/HEAD"),
            "ref: refs/heads/feat/footer\n",
        )
        .unwrap();
        let nested = repo.path().join("crates/app");
        std::fs::create_dir_all(&nested).unwrap();
        let status = FooterStatus {
            branch: read_git_branch(&nested),
            tokens: TokenTotals::from_stats(&serde_json::json!({
                "tokens": { "input": 12_345, "output": 800, "cacheRead": 2_500_000, "cacheWrite": 0 }
            })),
            cache_hit_percent: cache_hit_percent(&serde_json::json!({
                "usage": { "input": 100, "cacheRead": 300, "cacheWrite": 100 }
            })),
        };
        let theme = Theme::builtin("prime", crate::theme::ColorMode::TrueColor);
        let row = render_footer_status("/work/app", &status, &theme, 60).unwrap();
        assert_eq!(
            text(&row),
            format!(
                "/work/app (feat/footer){}\u{2191}12k \u{2193}800 R2.5M CH60.0%",
                " ".repeat(14)
            )
        );
        let narrow = render_footer_status("/work/app", &status, &theme, 30).unwrap();
        assert_eq!(
            text(&narrow),
            "/work/app (feat/footer)  \u{2191}12k\u{2026}"
        );
    }

    #[test]
    fn the_activity_dock_stays_clickable_below_the_footer_row() {
        use crate::chrome::{ActivityDock, ActivityGroup};
        use crate::view::click::ClickAction;
        let mut view = crate::view::AgentView::new(Theme::builtin(
            "prime",
            crate::theme::ColorMode::TrueColor,
        ));
        view.chrome.cwd = "/w".to_string();
        view.chrome.activity = Some(ActivityDock {
            heartbeats: 1,
            ..Default::default()
        });
        let frame = view.render_frame(80, 24);
        let (row, col) = frame
            .iter()
            .enumerate()
            .find_map(|(row, line)| {
                let text = text(line);
                text.find("heartbeat")
                    .map(|at| (row, str_width(&text[..at])))
            })
            .expect("the activity row renders");
        assert_eq!(
            text(&frame[row - 2]).trim(),
            "/w",
            "the footer row sits above the dock frame"
        );
        assert_eq!(
            view.click_target_at(row, col),
            Some(ClickAction::OpenDockGroup(ActivityGroup::Heartbeats))
        );
    }
}
