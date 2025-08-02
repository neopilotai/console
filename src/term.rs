use alloc::sync::Arc;
use core::fmt::{self, Debug, Display};
use std::io::{self, Read, Write};
#[cfg(any(unix, all(target_os = "wasi", target_env = "p1")))]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Mutex, RwLock};

use crate::{kb::Key, utils::Style};

#[cfg(unix)]
trait TermWrite: Write + Debug + AsRawFd + Send {}
#[cfg(unix)]
impl<T: Write + Debug + AsRawFd + Send> TermWrite for T {}

#[cfg(unix)]
trait TermRead: Read + Debug + AsRawFd + Send {}
#[cfg(unix)]
impl<T: Read + Debug + AsRawFd + Send> TermRead for T {}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ReadWritePair {
    read: Arc<Mutex<dyn TermRead>>,
    write: Arc<Mutex<dyn TermWrite>>,
    style: Style,
}

/// Where the term is writing.
#[derive(Debug, Clone)]
pub enum TermTarget {
    Stdout,
    Stderr,
    #[cfg(unix)]
    ReadWritePair(ReadWritePair),
}

pub struct TermInner {
    pub target: TermTarget,
    pub read_key: Option<Arc<dyn Fn() -> io::Result<Key> + Send + Sync>>,
    pub buffer: Option<Mutex<Vec<u8>>>,
    pub prompt: RwLock<String>,
    pub prompt_guard: Mutex<()>,
}

impl fmt::Debug for TermInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TermInner")
            .field("target", &self.target)
            .field("buffer", &self.buffer)
            .finish()
    }
}

/// Terminal family.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TermFamily {
    File,
    UnixTerm,
    WindowsConsole,
    Dummy,
}

/// Terminal features.
#[derive(Debug, Clone)]
pub struct TermFeatures<'a>(&'a Term);

impl TermFeatures<'_> {
    #[inline]
    pub fn is_attended(&self) -> bool {
        is_a_terminal(self.0)
    }

    #[inline]
    pub fn colors_supported(&self) -> bool {
        is_a_color_terminal(self.0)
    }

    #[inline]
    pub fn is_msys_tty(&self) -> bool {
        #[cfg(windows)]
        {
            msys_tty_on(self.0)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    #[inline]
    pub fn wants_emoji(&self) -> bool {
        self.is_attended() && wants_emoji()
    }

    #[inline]
    pub fn family(&self) -> TermFamily {
        if !self.is_attended() {
            return TermFamily::File;
        }
        #[cfg(windows)]
        {
            TermFamily::WindowsConsole
        }
        #[cfg(all(unix, not(target_arch = "wasm32")))]
        {
            TermFamily::UnixTerm
        }
        #[cfg(target_arch = "wasm32")]
        {
            TermFamily::Dummy
        }
    }
}

/// Terminal abstraction.
#[derive(Clone, Debug)]
pub struct Term {
    inner: Arc<TermInner>,
    pub(crate) is_msys_tty: bool,
    pub(crate) is_tty: bool,
}

impl Term {
    fn build_inner(mut inner: TermInner) -> Term {
        let arc = Arc::new(inner);
        let term = Term {
            inner: arc,
            is_msys_tty: false,
            is_tty: false,
        };
        let mut term = term;
        term.is_msys_tty = term.features().is_msys_tty();
        term.is_tty = term.features().is_attended();
        term
    }

    #[inline]
    pub fn stdout() -> Term {
        Self::build_inner(TermInner {
            target: TermTarget::Stdout,
            read_key: None,
            buffer: None,
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    #[inline]
    pub fn stderr() -> Term {
        Self::build_inner(TermInner {
            target: TermTarget::Stderr,
            read_key: None,
            buffer: None,
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    #[inline]
    pub fn stderr_with_read_key<F>(f: Arc<F>) -> Term
    where
        F: Fn() -> io::Result<Key> + Send + Sync + 'static,
    {
        Self::build_inner(TermInner {
            target: TermTarget::Stderr,
            read_key: Some(f),
            buffer: None,
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    pub fn buffered_stdout() -> Term {
        Self::build_inner(TermInner {
            target: TermTarget::Stdout,
            read_key: None,
            buffer: Some(Mutex::new(vec![])),
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    pub fn buffered_stderr() -> Term {
        Self::build_inner(TermInner {
            target: TermTarget::Stderr,
            read_key: None,
            buffer: Some(Mutex::new(vec![])),
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    #[cfg(unix)]
    pub fn read_write_pair<R, W>(read: R, write: W) -> Term
    where
        R: Read + Debug + AsRawFd + Send + 'static,
        W: Write + Debug + AsRawFd + Send + 'static,
    {
        Self::read_write_pair_with_style(read, write, Style::new().for_stderr())
    }

    #[cfg(unix)]
    pub fn read_write_pair_with_style<R, W>(read: R, write: W, style: Style) -> Term
    where
        R: Read + Debug + AsRawFd + Send + 'static,
        W: Write + Debug + AsRawFd + Send + 'static,
    {
        Self::build_inner(TermInner {
            target: TermTarget::ReadWritePair(ReadWritePair {
                read: Arc::new(Mutex::new(read)),
                write: Arc::new(Mutex::new(write)),
                style,
            }),
            buffer: None,
            read_key: None,
            prompt: RwLock::new(String::new()),
            prompt_guard: Mutex::new(()),
        })
    }

    #[inline]
    pub fn style(&self) -> Style {
        match self.inner.target {
            TermTarget::Stderr => Style::new().for_stderr(),
            TermTarget::Stdout => Style::new().for_stdout(),
            #[cfg(unix)]
            TermTarget::ReadWritePair(ReadWritePair { ref style, .. }) => style.clone(),
        }
    }

    #[inline]
    pub fn target(&self) -> TermTarget {
        self.inner.target.clone()
    }

    pub fn write_str(&self, s: &str) -> io::Result<()> {
        match &self.inner.buffer {
            Some(buffer) => buffer
                .lock()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Lock poisoned: {e}")))?
                .write_all(s.as_bytes()),
            None => self.write_through(s.as_bytes()),
        }
    }

    pub fn write_line(&self, s: &str) -> io::Result<()> {
        let prompt = self.inner.prompt.read().unwrap();
        if !prompt.is_empty() {
            self.clear_line()?;
        }
        match &self.inner.buffer {
            Some(mutex) => {
                let mut buffer = mutex.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Lock poisoned: {e}")))?;
                buffer.extend_from_slice(s.as_bytes());
                buffer.push(b'\n');
                buffer.extend_from_slice(prompt.as_bytes());
                Ok(())
            }
            None => self.write_through(format!("{}\n{}", s, prompt.as_str()).as_bytes()),
        }
    }

    pub fn read_char(&self) -> io::Result<char> {
        if !self.is_tty {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Not a terminal"));
        }
        loop {
            match self.read_key()? {
                Key::Char(c) => return Ok(c),
                Key::Enter => return Ok('\n'),
                _ => {}
            }
        }
    }

    pub fn read_key(&self) -> io::Result<Key> {
        if !self.is_tty {
            Ok(Key::Unknown)
        } else if let Some(ref read_key) = self.inner.read_key {
            read_key()
        } else {
            read_single_key(false)
        }
    }

    pub fn read_key_raw(&self) -> io::Result<Key> {
        if !self.is_tty {
            Ok(Key::Unknown)
        } else {
            read_single_key(true)
        }
    }

    pub fn read_line(&self) -> io::Result<String> {
        self.read_line_initial_text("")
    }

    pub fn read_line_initial_text(&self, initial: &str) -> io::Result<String> {
        if !self.is_tty {
            return Ok(String::new());
        }
        *self.inner.prompt.write().unwrap() = initial.to_string();
        let _guard = self.inner.prompt_guard.lock().unwrap();

        self.write_str(initial)?;

        fn read_line_internal(slf: &Term, initial: &str) -> io::Result<String> {
            let prefix_len = initial.len();
            let mut chars: Vec<char> = initial.chars().collect();
            loop {
                match slf.read_key()? {
                    Key::Backspace => {
                        if prefix_len < chars.len() {
                            if let Some(ch) = chars.pop() {
                                slf.clear_chars(crate::utils::char_width(ch))?;
                            }
                        }
                        slf.flush()?;
                    }
                    Key::Char(chr) => {
                        chars.push(chr);
                        let mut bytes_char = [0; 4];
                        chr.encode_utf8(&mut bytes_char);
                        slf.write_str(chr.encode_utf8(&mut bytes_char))?;
                        slf.flush()?;
                    }
                    Key::Enter => {
                        slf.write_through(format!("\n{initial}").as_bytes())?;
                        break;
                    }
                    _ => (),
                }
            }
            Ok(chars.iter().skip(prefix_len).collect())
        }
        let ret = read_line_internal(self, initial);
        *self.inner.prompt.write().unwrap() = String::new();
        ret
    }

    pub fn read_secure_line(&self) -> io::Result<String> {
        if !self.is_tty {
            return Ok(String::new());
        }
        match read_secure() {
            Ok(rv) => {
                self.write_line("")?;
                Ok(rv)
            }
            Err(err) => Err(err),
        }
    }

    pub fn flush(&self) -> io::Result<()> {
        if let Some(ref buffer) = self.inner.buffer {
            let mut buffer = buffer.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Lock poisoned: {e}")))?;
            if !buffer.is_empty() {
                self.write_through(&buffer[..])?;
                buffer.clear();
            }
        }
        Ok(())
    }

    #[inline]
    pub fn is_term(&self) -> bool {
        self.is_tty
    }

    #[inline]
    pub fn features(&self) -> TermFeatures<'_> {
        TermFeatures(self)
    }

    #[inline]
    pub fn size(&self) -> (u16, u16) {
        self.size_checked().unwrap_or((24, DEFAULT_WIDTH))
    }

    #[inline]
    pub fn size_checked(&self) -> Option<(u16, u16)> {
        terminal_size(self)
    }

    #[inline]
    pub fn move_cursor_to(&self, x: usize, y: usize) -> io::Result<()> {
        move_cursor_to(self, x, y)
    }

    #[inline]
    pub fn move_cursor_up(&self, n: usize) -> io::Result<()> {
        move_cursor_up(self, n)
    }

    #[inline]
    pub fn move_cursor_down(&self, n: usize) -> io::Result<()> {
        move_cursor_down(self, n)
    }

    #[inline]
    pub fn move_cursor_left(&self, n: usize) -> io::Result<()> {
        move_cursor_left(self, n)
    }

    #[inline]
    pub fn move_cursor_right(&self, n: usize) -> io::Result<()> {
        move_cursor_right(self, n)
    }

    #[inline]
    pub fn clear_line(&self) -> io::Result<()> {
        clear_line(self)
    }

    pub fn clear_last_lines(&self, n: usize) -> io::Result<()> {
        self.move_cursor_up(n)?;
        for _ in 0..n {
            self.clear_line()?;
            self.move_cursor_down(1)?;
        }
        self.move_cursor_up(n)?;
        Ok(())
    }

    #[inline]
    pub fn clear_screen(&self) -> io::Result<()> {
        clear_screen(self)
    }

    #[inline]
    pub fn clear_to_end_of_screen(&self) -> io::Result<()> {
        clear_to_end_of_screen(self)
    }

    #[inline]
    pub fn clear_chars(&self, n: usize) -> io::Result<()> {
        clear_chars(self, n)
    }

    pub fn set_title<T: Display>(&self, title: T) {
        if self.is_tty {
            set_title(title);
        }
    }

    #[inline]
    pub fn show_cursor(&self) -> io::Result<()> {
        show_cursor(self)
    }

    #[inline]
    pub fn hide_cursor(&self) -> io::Result<()> {
        hide_cursor(self)
    }

    // Write-through helpers

    #[cfg(all(windows, feature = "windows-console-colors"))]
    fn write_through(&self, bytes: &[u8]) -> io::Result<()> {
        if self.is_msys_tty || !self.is_tty {
            self.write_through_common(bytes)
        } else {
            match self.inner.target {
                TermTarget::Stdout => console_colors(self, Console::stdout()?, bytes),
                TermTarget::Stderr => console_colors(self, Console::stderr()?, bytes),
            }
        }
    }

    #[cfg(not(all(windows, feature = "windows-console-colors")))]
    fn write_through(&self, bytes: &[u8]) -> io::Result<()> {
        self.write_through_common(bytes)
    }

    pub(crate) fn write_through_common(&self, bytes: &[u8]) -> io::Result<()> {
        match self.inner.target {
            TermTarget::Stdout => {
                io::stdout().write_all(bytes)?;
                io::stdout().flush()?;
            }
            TermTarget::Stderr => {
                io::stderr().write_all(bytes)?;
                io::stderr().flush()?;
            }
            #[cfg(unix)]
            TermTarget::ReadWritePair(ReadWritePair { ref write, .. }) => {
                let mut write = write.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Lock poisoned: {e}")))?;
                write.write_all(bytes)?;
                write.flush()?;
            }
        }
        Ok(())
    }
}

#[inline]
pub fn user_attended() -> bool {
    Term::stdout().features().is_attended()
}

#[inline]
pub fn user_attended_stderr() -> bool {
    Term::stderr().features().is_attended()
}

#[cfg(any(unix, all(target_os = "wasi", target_env = "p1")))]
impl AsRawFd for Term {
    fn as_raw_fd(&self) -> RawFd {
        match self.inner.target {
            TermTarget::Stdout => libc::STDOUT_FILENO,
            TermTarget::Stderr => libc::STDERR_FILENO,
            #[cfg(unix)]
            TermTarget::ReadWritePair(ReadWritePair { ref write, .. }) => {
                write.lock().unwrap().as_raw_fd()
            }
        }
    }
}

#[cfg(windows)]
impl AsRawHandle for Term {
    fn as_raw_handle(&self) -> RawHandle {
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        };

        unsafe {
            GetStdHandle(match self.inner.target {
                TermTarget::Stdout => STD_OUTPUT_HANDLE,
                TermTarget::Stderr => STD_ERROR_HANDLE,
            }) as RawHandle
        }
    }
}

// Unified Write impl for Term and &Term
macro_rules! impl_write_for_term {
    ($($t:ty),*) => {
        $(
            impl Write for $t {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    match &self.inner.buffer {
                        Some(buffer) => buffer.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Lock poisoned: {e}")))?.write_all(buf),
                        None => self.write_through(buf),
                    }?;
                    Ok(buf.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    Term::flush(self)
                }
            }
        )*
    };
}
impl_write_for_term!(Term, &Term);

impl Read for Term {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().read(buf)
    }
}
impl Read for &Term {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().read(buf)
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
pub(crate) use crate::unix_term::*;
#[cfg(target_arch = "wasm32")]
pub(crate) use crate::wasm_term::*;
#[cfg(windows)]
pub(crate) use crate::windows_term::*;
