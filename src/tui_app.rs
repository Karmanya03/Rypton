/// TUI module: interactive terminal dashboard using ratatui.
use crate::vault;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{prelude::*, widgets::*};
use std::io;

struct App {
    items: Vec<vault::VaultItem>,
    selected: usize,
    quit: bool,
}

impl App {
    fn new() -> Result<Self> {
        let items = vault::list_items().unwrap_or_default();
        Ok(Self {
            items,
            selected: 0,
            quit: false,
        })
    }

    fn next(&mut self) {
        if !self.items.is_empty() {
            self.selected = (self.selected + 1) % self.items.len();
        }
    }

    fn previous(&mut self) {
        if !self.items.is_empty() {
            self.selected = self.selected.checked_sub(1).unwrap_or(self.items.len() - 1);
        }
    }
}

pub fn run() -> Result<()> {
    if !vault::is_initialized() {
        println!("Vault not initialized. Run 'rypton init' first.");
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new()?;

    while !app.quit {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.previous(),
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn ui(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    // Header
    let header_text = vec![
        Line::from(Span::styled(
            "  RYPTON VAULT DASHBOARD",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  XChaCha20-Poly1305 + Argon2id + HKDF-SHA256",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header, chunks[0]);

    // Item list
    let items_block = Block::default()
        .title(Span::styled(
            format!(" Vault Items ({}) ", app.items.len()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    if app.items.is_empty() {
        let empty =
            Paragraph::new("  No items in vault. Use 'rypton vault add <path>' to add files.")
                .style(Style::default().fg(Color::DarkGray))
                .block(items_block);
        frame.render_widget(empty, chunks[1]);
    } else {
        let detail_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(chunks[1]);

        let list_items: Vec<ListItem> = app
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let type_str = match item.item_type {
                    vault::VaultItemType::Ssh => "[SSH]",
                    vault::VaultItemType::Shadow => "[SHD]",
                    vault::VaultItemType::Custom => "[CUS]",
                    vault::VaultItemType::Folder => "[DIR]",
                    vault::VaultItemType::SystemSsh => "[S:S]",
                    vault::VaultItemType::SystemShadow => "[S:H]",
                    vault::VaultItemType::SystemCert => "[S:C]",
                    vault::VaultItemType::SystemConfig => "[S:G]",
                };
                let type_color = match item.item_type {
                    vault::VaultItemType::Ssh => Color::Red,
                    vault::VaultItemType::Shadow => Color::Magenta,
                    vault::VaultItemType::Custom => Color::Blue,
                    vault::VaultItemType::Folder => Color::Yellow,
                    vault::VaultItemType::SystemSsh => Color::LightRed,
                    vault::VaultItemType::SystemShadow => Color::LightMagenta,
                    vault::VaultItemType::SystemCert => Color::LightGreen,
                    vault::VaultItemType::SystemConfig => Color::LightCyan,
                };

                let style = if i == app.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!(" {} ", type_str), Style::default().fg(type_color)),
                    Span::styled(item.name.to_string(), style),
                ]))
            })
            .collect();

        let list = List::new(list_items)
            .block(items_block)
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(list, detail_chunks[0]);

        // Detail panel
        if let Some(item) = app.items.get(app.selected) {
            let _short_id = if item.id.len() > 8 {
                &item.id[..8]
            } else {
                &item.id
            };
            let size = if item.size_bytes > 1024 {
                format!("{:.1} KB", item.size_bytes as f64 / 1024.0)
            } else {
                format!("{} B", item.size_bytes)
            };

            let detail_text = vec![
                Line::from(vec![
                    Span::styled("  ID:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&item.id, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Name:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&item.name, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("  Type:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        item.item_type.to_string(),
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Size:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(size, Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled("  Path:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&item.original_path, Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  BLAKE3: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        if item.blake3_hash.len() > 16 {
                            &item.blake3_hash[..16]
                        } else {
                            &item.blake3_hash
                        },
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled("...", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(vec![
                    Span::styled("  Added:  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        item.created_at.format("%Y-%m-%d %H:%M").to_string(),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];

            let detail = Paragraph::new(detail_text).block(
                Block::default()
                    .title(Span::styled(
                        " Details ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            frame.render_widget(detail, detail_chunks[1]);
        }
    }

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" j/k ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(" Navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::styled(" Quit  ", Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[2]);
}
