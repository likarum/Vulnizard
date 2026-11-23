//! Server-rendered SVG charts (no JavaScript).
//!
//! Colors are CSS classes (`fill-*` / `stroke-*`) defined in the stylesheet,
//! so the light and dark themes are selected in one place and no inline
//! style is needed (the Content-Security-Policy forbids it). Every value shown
//! in a chart is also printed in its legend or in a table next to it; the
//! `<title>` elements only add a native tooltip.

use maud::{html, Markup};

use crate::db::DayStats;

/// Categorical slots available for projects; further projects fold into "Other"
pub const PROJECT_SLOTS: usize = 7;

/// Color key of a project slot (the 8th class is the neutral "Other")
pub fn project_color(slot: usize) -> String {
    if slot < PROJECT_SLOTS {
        format!("p{slot}")
    } else {
        "other".to_string()
    }
}

pub const SEVERITIES: [(&str, &str, &str); 5] = [
    ("critical", "Critical", "sev-critical"),
    ("high", "High", "sev-high"),
    ("medium", "Medium", "sev-medium"),
    ("low", "Low", "sev-low"),
    ("none", "No score", "sev-none"),
];

pub const STATUSES: [(&str, &str, &str); 4] = [
    ("untreated", "To review", "st-open"),
    ("accepted", "Risk accepted", "st-accepted"),
    ("treated", "Closed", "st-closed"),
    ("not_applicable", "Not applicable", "st-na"),
];

pub fn status_label(status: &str) -> &'static str {
    STATUSES
        .iter()
        .find(|(key, _, _)| *key == status)
        .map(|(_, label, _)| *label)
        .unwrap_or("Unknown")
}

pub fn status_color(status: &str) -> &'static str {
    STATUSES
        .iter()
        .find(|(key, _, _)| *key == status)
        .map(|(_, _, color)| *color)
        .unwrap_or("st-na")
}

/// One part of a whole
#[derive(Clone)]
pub struct Segment {
    pub label: String,
    pub value: i64,
    /// Color key: the classes `fill-<color>` and `stroke-<color>` exist in the stylesheet
    pub color: String,
}

impl Segment {
    pub fn new(label: impl Into<String>, value: i64, color: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value,
            color: color.into(),
        }
    }
}

fn swatch(color: &str) -> Markup {
    html! {
        svg.swatch width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" {
            rect width="10" height="10" rx="2" class={ "fill-" (color) } {}
        }
    }
}

/// Legend listing every segment with its value (identity is never color alone)
pub fn legend(segments: &[Segment], with_values: bool) -> Markup {
    html! {
        ul.legend {
            @for s in segments {
                li {
                    (swatch(&s.color)) " " (s.label)
                    @if with_values { " " strong { (s.value) } }
                }
            }
        }
    }
}

/// Donut: parts of a whole, total in the centre
pub fn donut(segments: &[Segment], total_label: &str) -> Markup {
    const R: f64 = 54.0;
    const GAP: f64 = 2.0;
    let total: i64 = segments.iter().map(|s| s.value).sum();
    let circumference = 2.0 * std::f64::consts::PI * R;
    let visible: Vec<&Segment> = segments.iter().filter(|s| s.value > 0).collect();
    let mut offset = 0.0;
    html! {
        div.chart.donut {
            svg viewBox="0 0 140 140" width="140" height="140" role="img"
                aria-label={ (total_label) ": " (total) } {
                @if total == 0 {
                    circle cx="70" cy="70" r=(R) class="stroke-track" stroke-width="16" {}
                }
                // Starts at 12 o'clock, clockwise
                g transform="rotate(-90 70 70)" {
                    @for s in &visible {
                        @let share = s.value as f64 / total as f64 * circumference;
                        // 2px surface gap between segments (none for a single one)
                        @let len = if visible.len() > 1 { (share - GAP).max(1.0) } else { share };
                        circle cx="70" cy="70" r=(R) class={ "stroke-" (s.color) } stroke-width="16"
                            stroke-dasharray={ (format!("{len:.2}")) " " (format!("{:.2}", circumference - len)) }
                            stroke-dashoffset=(format!("{:.2}", -offset)) {
                            title { (s.label) ": " (s.value) }
                        }
                        @let _ = { offset += share; };
                    }
                }
                text.total x="70" y="68" text-anchor="middle" { (total) }
                text.caption x="70" y="84" text-anchor="middle" { (total_label) }
            }
            (legend(segments, true))
        }
    }
}

/// Horizontal stacked bars: one row per category, segments sharing one legend
pub fn stacked_rows(rows: &[(String, Vec<Segment>)], legend_segments: &[Segment]) -> Markup {
    const LABEL_W: f64 = 84.0;
    const PLOT_W: f64 = 212.0;
    const ROW_H: f64 = 26.0;
    const BAR_H: f64 = 14.0;
    const GAP: f64 = 2.0;
    let max: i64 = rows
        .iter()
        .map(|(_, segs)| segs.iter().map(|s| s.value).sum::<i64>())
        .max()
        .unwrap_or(0)
        .max(1);
    let height = rows.len() as f64 * ROW_H + 4.0;
    html! {
        div.chart {
            svg viewBox={ "0 0 340 " (height) } width="340" height=(height) role="img" {
                @for (i, (label, segs)) in rows.iter().enumerate() {
                    @let y = i as f64 * ROW_H + 4.0;
                    @let total: i64 = segs.iter().map(|s| s.value).sum();
                    text.label x=(LABEL_W - 8.0) y=(y + 11.0) text-anchor="end" { (label) }
                    rect x=(LABEL_W) y=(y) width=(PLOT_W) height=(BAR_H) rx="4" class="fill-track" {}
                    @let mut x = LABEL_W;
                    @for s in segs.iter().filter(|s| s.value > 0) {
                        @let w = s.value as f64 / max as f64 * PLOT_W;
                        rect x=(format!("{x:.1}")) y=(y) width=(format!("{:.1}", (w - GAP).max(1.0))) height=(BAR_H) rx="3"
                            class={ "fill-" (s.color) } {
                            title { (label) " · " (s.label) ": " (s.value) }
                        }
                        @let _ = { x += w; };
                    }
                    text.value x=(LABEL_W + PLOT_W + 8.0) y=(y + 11.0) { (total) }
                }
            }
            @if legend_segments.len() > 1 { (legend(legend_segments, false)) }
        }
    }
}

const CHART_W: f64 = 1100.0;
const PLOT_LEFT: f64 = 36.0;
const PLOT_RIGHT: f64 = 12.0;

fn nice_max(value: i64) -> i64 {
    let value = value.max(4);
    let magnitude = 10_i64.pow((value as f64).log10().floor() as u32);
    for step in [1, 2, 4, 5, 10] {
        if step * magnitude >= value {
            return step * magnitude;
        }
    }
    10 * magnitude
}

/// Shared frame of the time charts: gridlines, y ticks, first/middle/last dates
fn time_frame(days: &[DayStats], max: i64, plot_h: f64) -> Markup {
    let plot_w = CHART_W - PLOT_LEFT - PLOT_RIGHT;
    let label_days: Vec<usize> = match days.len() {
        0 => vec![],
        1 => vec![0],
        n => vec![0, n / 2, n - 1],
    };
    html! {
        @for tick in [0, max / 2, max] {
            @let y = 8.0 + plot_h - tick as f64 / max as f64 * plot_h;
            line.grid x1=(PLOT_LEFT) x2=(CHART_W - PLOT_RIGHT) y1=(y) y2=(y) {}
            text.label x=(PLOT_LEFT - 6.0) y=(y + 4.0) text-anchor="end" { (tick) }
        }
        @for i in label_days {
            @let x = PLOT_LEFT + (i as f64 + 0.5) * plot_w / days.len() as f64;
            text.label x=(x) y=(plot_h + 26.0)
                text-anchor=(if i == 0 { "start" } else if i == days.len() - 1 { "end" } else { "middle" }) {
                (days[i].day)
            }
        }
    }
}

/// Transparent per-day columns: tooltip, link to that day, marker of the selected one
fn day_targets(
    days: &[DayStats],
    plot_h: f64,
    selected: Option<&str>,
    link: &dyn Fn(&str) -> String,
    describe: &dyn Fn(&DayStats) -> String,
) -> Markup {
    let plot_w = CHART_W - PLOT_LEFT - PLOT_RIGHT;
    let col = plot_w / days.len().max(1) as f64;
    html! {
        @for (i, d) in days.iter().enumerate() {
            @let x = PLOT_LEFT + i as f64 * col;
            @if selected == Some(d.day.as_str()) {
                rect.selected x=(format!("{x:.1}")) y="8" width=(format!("{col:.1}")) height=(plot_h) {}
            }
            a href=(link(&d.day)) {
                rect.hit x=(format!("{x:.1}")) y="8" width=(format!("{col:.1}")) height=(plot_h) {
                    title { (d.day) " — " (describe(d)) }
                }
            }
        }
    }
}

/// Stock over time: entries still to review, and accepted risks (same unit, one axis)
pub fn stock_chart(days: &[DayStats], selected: Option<&str>, link: &dyn Fn(&str) -> String) -> Markup {
    const PLOT_H: f64 = 150.0;
    let plot_w = CHART_W - PLOT_LEFT - PLOT_RIGHT;
    let max = nice_max(days.iter().map(|d| d.open.max(d.accepted_total)).max().unwrap_or(0));
    let col = plot_w / days.len().max(1) as f64;
    let points = |value: &dyn Fn(&DayStats) -> i64| -> String {
        days.iter()
            .enumerate()
            .map(|(i, d)| {
                format!(
                    "{:.1},{:.1}",
                    PLOT_LEFT + (i as f64 + 0.5) * col,
                    8.0 + PLOT_H - value(d) as f64 / max as f64 * PLOT_H
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let last = days.last();
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (PLOT_H + 34.0) } role="img"
                aria-label="CVEs to review and accepted risks over time" {
                (time_frame(days, max, PLOT_H))
                polyline class="series stroke-st-accepted" points=(points(&|d| d.accepted_total)) {}
                polyline class="series stroke-st-open" points=(points(&|d| d.open)) {}
                (day_targets(days, PLOT_H, selected, link, &|d| format!("{} to review, {} accepted", d.open, d.accepted_total)))
            }
            (legend(&[
                Segment::new("To review", last.map(|d| d.open).unwrap_or(0), "st-open"),
                Segment::new("Risk accepted", last.map(|d| d.accepted_total).unwrap_or(0), "st-accepted"),
            ], true))
        }
    }
}

/// Daily activity: new entries and decisions, stacked per day
pub fn activity_chart(days: &[DayStats], selected: Option<&str>, link: &dyn Fn(&str) -> String) -> Markup {
    const PLOT_H: f64 = 120.0;
    let plot_w = CHART_W - PLOT_LEFT - PLOT_RIGHT;
    let parts = |d: &DayStats| {
        [
            (d.new + d.reopened, "st-open"),
            (d.accepted, "st-accepted"),
            (d.closed, "st-closed"),
            (d.not_applicable, "st-na"),
        ]
    };
    let max = nice_max(
        days.iter()
            .map(|d| parts(d).iter().map(|(v, _)| v).sum::<i64>())
            .max()
            .unwrap_or(0),
    );
    let col = plot_w / days.len().max(1) as f64;
    // Thin marks, with a gap between neighbouring days when there is room
    let bar_w = (col - 2.0).clamp(1.0, 18.0);
    let sum = |f: &dyn Fn(&DayStats) -> i64| days.iter().map(f).sum::<i64>();
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (PLOT_H + 34.0) } role="img"
                aria-label="New entries and decisions per day" {
                (time_frame(days, max, PLOT_H))
                @for (i, d) in days.iter().enumerate() {
                    @let x = PLOT_LEFT + i as f64 * col + (col - bar_w) / 2.0;
                    @let mut y = 8.0 + PLOT_H;
                    @for (value, color) in parts(d) {
                        @if value > 0 {
                            @let h = value as f64 / max as f64 * PLOT_H;
                            @let _ = { y -= h; };
                            rect x=(format!("{x:.1}")) y=(format!("{y:.1}")) width=(format!("{bar_w:.1}"))
                                height=(format!("{:.1}", (h - 1.0).max(1.0))) rx="1.5" class={ "fill-" (color) } {}
                        }
                    }
                }
                (day_targets(days, PLOT_H, selected, link, &|d| format!(
                    "{} new, {} accepted, {} closed, {} not applicable",
                    d.new + d.reopened, d.accepted, d.closed, d.not_applicable
                )))
            }
            (legend(&[
                Segment::new("New or reopened", sum(&|d| d.new + d.reopened), "st-open"),
                Segment::new("Risk accepted", sum(&|d| d.accepted), "st-accepted"),
                Segment::new("Closed", sum(&|d| d.closed), "st-closed"),
                Segment::new("Not applicable", sum(&|d| d.not_applicable), "st-na"),
            ], true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donut_draws_one_arc_per_non_empty_segment() {
        let svg = donut(
            &[
                Segment::new("io", 3, "p0"),
                Segment::new("pawn", 1, "p1"),
                Segment::new("empty", 0, "p2"),
            ],
            "to review",
        )
        .into_string();
        assert_eq!(svg.matches("<circle").count(), 2);
        assert!(svg.contains("stroke-p0") && svg.contains("stroke-p1") && !svg.contains("stroke-p2"));
        assert!(svg.contains(">4</text>"));
        // Every segment, even empty, is named in the legend
        assert!(svg.contains("empty"));
        // No inline style: the CSP forbids it
        assert!(!svg.contains("style="));
    }

    #[test]
    fn svg_elements_are_explicitly_closed() {
        // In HTML an SVG element is never void: an unclosed <rect> would swallow what follows
        let days = vec![DayStats { day: "2026-01-01".into(), new: 2, open: 2, ..Default::default() }];
        let link = |d: &str| d.to_string();
        let rows = vec![("io".to_string(), vec![Segment::new("a", 2, "p0"), Segment::new("b", 1, "p1")])];
        for svg in [
            donut(&[Segment::new("a", 1, "p0"), Segment::new("b", 2, "p1")], "t").into_string(),
            stacked_rows(&rows, &rows[0].1).into_string(),
            stock_chart(&days, Some("2026-01-01"), &link).into_string(),
            activity_chart(&days, None, &link).into_string(),
        ] {
            // A repeated attribute is dropped by the browser (the color would be lost)
            assert!(!svg.contains("\" class=\"") || !regex::Regex::new(r#"<[a-z]+ [^>]*class="[^"]*"[^>]*class=""#).unwrap().is_match(&svg));
            for tag in ["rect", "circle", "line", "polyline"] {
                assert_eq!(
                    svg.matches(&format!("<{tag} ")).count(),
                    svg.matches(&format!("</{tag}>")).count(),
                    "unclosed <{tag}>"
                );
            }
        }
    }

    #[test]
    fn empty_donut_shows_a_track_and_zero() {
        let svg = donut(&[Segment::new("io", 0, "p0")], "to review").into_string();
        assert!(svg.contains("stroke-track"));
        assert!(svg.contains(">0</text>"));
    }

    #[test]
    fn labels_are_escaped() {
        let svg = donut(&[Segment::new("<script>x</script>", 1, "p0")], "t").into_string();
        assert!(!svg.contains("<script>"));
    }

    #[test]
    fn time_charts_link_every_day_and_scale_nicely() {
        let days: Vec<DayStats> = (1..=3)
            .map(|i| DayStats {
                day: format!("2026-01-0{i}"),
                new: i,
                open: i * 3,
                ..Default::default()
            })
            .collect();
        let link = |day: &str| format!("/product?view=history&at={day}");
        let stock = stock_chart(&days, Some("2026-01-02"), &link).into_string();
        assert_eq!(stock.matches("<a href=").count(), 3);
        assert_eq!(stock.matches("class=\"selected\"").count(), 1);
        assert!(stock.contains("at=2026-01-03"));
        let activity = activity_chart(&days, None, &link).into_string();
        assert_eq!(activity.matches("fill-st-open").count(), 3 + 1); // three bars + legend
        assert_eq!((nice_max(0), nice_max(9), nice_max(37), nice_max(120)), (4, 10, 40, 200));
        assert!(stock_chart(&[], None, &link).into_string().contains("<svg"));
    }

    #[test]
    fn projects_beyond_the_palette_fold_into_other() {
        assert_eq!(project_color(0), "p0");
        assert_eq!(project_color(PROJECT_SLOTS - 1), "p6");
        assert_eq!(project_color(PROJECT_SLOTS), "other");
        assert_eq!(project_color(40), "other");
    }
}
