use crate::WebauthnNotifier;
use indicatif::{ProgressBar, ProgressStyle};

pub struct ProgressBarFallbackNotifier {
    progress_bar: ProgressBar,
}

impl ProgressBarFallbackNotifier {
    pub fn new() -> Self {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&[
                    "▹▹▹▹▹",
                    "▸▹▹▹▹",
                    "▹▸▹▹▹",
                    "▹▹▸▹▹",
                    "▹▹▹▸▹",
                    "▹▹▹▹▸",
                    "▪▪▪▪▪",
                ])
                .template("{spinner:.blue} {msg}"),
        );

        Self { progress_bar: pb }
    }
}

impl WebauthnNotifier for ProgressBarFallbackNotifier {
    fn notify_start(&self) -> anyhow::Result<()> {
        self.progress_bar
            .set_message("Please insert and activate your U2F device...");

        Ok(())
    }

    fn notify_end(&self) -> anyhow::Result<()> {
        self.progress_bar
            .finish_with_message("Processing sign request...");

        Ok(())
    }
}
