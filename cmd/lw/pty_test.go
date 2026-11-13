//go:build linux || freebsd

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/testutil"
)

// asLw has the test binary run as lw, so a test starts it in a
// pseudo-terminal as a terminal emulator or sshd starts lw
const asLw = "LW_TEST_AS_LW"

func TestMain(m *testing.M) {
	if os.Getenv(asLw) != "" {
		main()
		os.Exit(0) // r's pipelines ended, as lw exits once they do
	}
	os.Exit(m.Run())
}

// The size of a tty, and how long it waits for what it expects
const (
	ttyW, ttyH = 120, 32
	ttyWait    = 20 * time.Second
)

// On a terminal, t runs the pipelines under the screen and shows what flows;
// q, confirmed, stops them, so the sink holds every entry, and lw exits with
// the terminal as it found it
func TestOnATerminalTRunsThePipelinesAndQStopsThem(t *testing.T) {
	t.Parallel()
	args, out := filePipeline(t)
	s := startTTY(t, true, append([]string{"-T"}, args...)...)
	s.waitFor("SOURCES", "t tap")
	s.keys("t")
	s.waitFor("running · 3 in · 0 filtered", "alpha one", "charlie three")
	s.keys("q")
	s.waitFor("Stop the pipelines and quit?")
	s.keys("y")
	s.exitsRestored()
	s.sunkAll(out)
}

// o prints the form chosen once the screen closes, on the main screen, where
// it reads back to the pipelines composed
func TestOnATerminalOPrintsEachForm(t *testing.T) {
	t.Parallel()
	args, _ := filePipeline(t)
	want, err := compose.FromCommandLine("lw "+strings.Join(args[2:], " "), config.HostIsDir) // past -c FILE
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range compose.Forms() {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			s := startTTY(t, true, append([]string{"-T"}, args...)...)
			s.waitFor("t tap")
			s.keys("o")
			s.waitFor("print " + f.Hint)
			s.keys(f.Name[:1])
			s.exitsRestored()
			if got, err := f.Read(s.printed(), config.HostIsDir); err != nil || !reflect.DeepEqual(got.Pipelines, want.Pipelines) {
				s.fatalf("read back: %+v, %v; want %+v", got, err, want.Pipelines)
			}
		})
	}
}

// r leaves the screen to run the pipelines in its place, the terminal cooked
// again: the console source reads the lines typed, Ctrl-D ends its input,
// and lw exits as the input ended
func TestOnATerminalRRunsThePipelinesInTheScreensPlace(t *testing.T) {
	t.Parallel()
	cfg := filepath.Join(t.TempDir(), "lw.toml")
	testutil.WriteFile(t, cfg, "")
	s := startTTY(t, true, "-T", "-c", cfg, "--logging.level=warn",
		"--pipeline", "p", "--source", "console", "--format", "json", "--sink", "console")
	s.waitFor("t tap")
	s.keys("r")
	s.untilPrinted("lw: reading standard input")
	s.keys("hello world\n")
	s.untilPrinted(`"fields":["hello world"]`)
	s.keys("\x04")
	s.exitsRestored()
}

// A password the terminal would be asked for is asked on the screen,
// masked, and the run goes on once it is given
func TestOnATerminalAPasswordIsAskedOnTheScreen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "lw.toml")
	testutil.WriteFile(t, cfg, "")
	s := startTTY(t, true, "-T", "-c", cfg, "--pipeline", "p", "--preset",
		"edge:path="+dir+",to=127.0.0.1:9,pin=sha256//"+strings.Repeat("A", 43)+"=,user=on-screen,password_file=/dev/tty")
	s.waitFor("t tap")
	s.keys("t")
	s.waitFor("Password for on-screen", "starting…")
	s.keys("s3cret")
	s.waitFor("password * ******")
	if strings.Contains(s.screen(), "s3cret") {
		s.fatalf("the password shows")
	}
	s.keys("\r")
	s.waitFor("running · 0 in")
	s.keys("q")
	s.waitFor("Stop the pipelines and quit?")
	s.keys("y")
	s.exitsRestored()
}

// SIGHUP, as sshd sends when the connection drops, stops the pipelines and
// leaves, the sink holding every entry
func TestOnATerminalSIGHUPStopsThePipelinesAndLeaves(t *testing.T) {
	t.Parallel()
	args, out := filePipeline(t)
	s := startTTY(t, true, append([]string{"-T"}, args...)...)
	s.waitFor("t tap")
	s.keys("t")
	s.waitFor("running · 3 in")
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	s.exitsRestored()
	s.sunkAll(out)
}

// What lw warns of while q stops the pipelines, a sink's lost batch, shows
// on no frame: it is printed once the screen closes
func TestOnATerminalTheStopsWarningsArePrinted(t *testing.T) {
	t.Parallel()
	args, _ := filePipeline(t)
	args[len(args)-1] = "http_chain:host=127.0.0.1,port=9" // refused: the batch waits
	s := startTTY(t, true, append([]string{"-T"}, args...)...)
	s.waitFor("t tap")
	s.keys("t")
	s.waitFor("running · 3 in")
	s.keys("q")
	s.waitFor("Stop the pipelines and quit?")
	s.keys("y")
	s.exitsRestored()
	if !strings.Contains(s.printed(), "Chain batch dropped on shutdown") {
		s.fatalf("the stop's warning was not printed")
	}
}

// A hangup that signals nothing, the terminal not lw's controlling one,
// fails the screen's read: lw stops the pipelines and leaves as on SIGHUP,
// where it waited for a key no hung up terminal sends
func TestOnATerminalAHangupWithoutSIGHUPLeaves(t *testing.T) {
	t.Parallel()
	args, out := filePipeline(t)
	s := startTTY(t, false, append([]string{"-T"}, args...)...)
	s.waitFor("t tap")
	s.keys("t")
	s.waitFor("running · 3 in")
	s.pty.Close()
	if code := s.exit(); code != 0 {
		s.fatalf("exit status %d", code)
	}
	s.sunkAll(out)
}

// filePipeline is a pipeline from a directory's app.log, read from its
// start, to a file sink: lw's arguments, and the directory the sink writes
func filePipeline(t *testing.T) (args []string, out string) {
	t.Helper()
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	for _, d := range []string{in, out} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(in, "app.log"), "alpha one\nbravo two\ncharlie three\n")
	cfg := filepath.Join(dir, "lw.toml")
	testutil.WriteFile(t, cfg, "")
	return []string{"-c", cfg, "--pipeline", "p", "--source", "file:directory=" + in + ",from=start",
		"--sink", "file:directory=" + out + ",name=out"}, out
}

// sunkAll fails unless the file sink wrote to dir every entry of app.log
func (s *tty) sunkAll(dir string) {
	s.t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		s.t.Fatal(err)
	}
	var all strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			s.t.Fatal(err)
		}
		all.Write(data)
	}
	for _, msg := range []string{"alpha one", "bravo two", "charlie three"} {
		if !strings.Contains(all.String(), msg) {
			s.fatalf("the sink missed %q: it wrote %q", msg, all.String())
		}
	}
}

// tty is lw in a pseudo-terminal. With a controlling terminal it is a
// login over ssh: closing the master hangs up and signals SIGHUP; without
// one, a hangup is a read that fails.
type tty struct {
	t     *testing.T
	cmd   *exec.Cmd
	pty   *os.File // the master: the terminal emulator's side; closing it hangs up
	mu    sync.Mutex
	vt    *vt
	read  chan struct{} // closed once the master reads no more: lw's output is all in vt
	done  chan struct{} // closed once lw exited
	state *os.ProcessState
}

func startTTY(t *testing.T, ctty bool, args ...string) *tty {
	t.Helper()
	master, slave := openPty(t)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = ttyEnv()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: ctty} // Ctty 0, its stdin
	err := cmd.Start()
	slave.Close()
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	s := &tty{t: t, cmd: cmd, pty: master, vt: newVT(ttyW, ttyH), read: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.read)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			s.mu.Lock()
			s.vt.write(buf[:n])
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		cmd.Wait()
		s.mu.Lock()
		s.state = cmd.ProcessState
		s.mu.Unlock()
		close(s.done)
	}()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			cmd.Process.Kill()
			<-s.done
		}
		master.Close()
	})
	return s
}

// ttyEnv is the test's environment as lw's in a UTF-8 xterm: no LogWisp
// settings, nor the color and locale settings that change what lw draws
func ttyEnv() []string {
	env := []string{asLw + "=1", "TERM=xterm-256color", "LANG=C.UTF-8"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(name, "LOGWISP_"), strings.HasPrefix(name, "LC_"),
			name == "LANG", name == "TERM", name == "COLORTERM", name == "NO_COLOR", name == asLw:
			continue
		}
		env = append(env, kv)
	}
	return env
}

// openPty opens a pseudo-terminal of the tty size: its master, and
// its terminal for lw
func openPty(t *testing.T) (master, terminal *os.File) {
	t.Helper()
	m, err := openPtyMaster()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	var n uint32
	if err := ioctl(m, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		m.Close()
		t.Fatal(err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	size := struct{ rows, cols, x, y uint16 }{ttyH, ttyW, 0, 0}
	if err := ioctl(s, syscall.TIOCSWINSZ, unsafe.Pointer(&size)); err != nil {
		m.Close()
		s.Close()
		t.Fatal(err)
	}
	return m, s
}

// ioctl makes request of f's descriptor without taking it from the poller
func ioctl(f *os.File, request uint, arg unsafe.Pointer) error {
	c, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	if err := c.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// screen is what the alternate screen shows
func (s *tty) screen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vt.screen()
}

// printed is the text written to the main screen
func (s *tty) printed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vt.printed.String()
}

// keys types k, as the terminal sends it
func (s *tty) keys(k string) {
	s.t.Helper()
	if _, err := s.pty.Write([]byte(k)); err != nil {
		s.fatalf("typing %q: %v", k, err)
	}
}

// waitFor waits until the screen shows each of want
func (s *tty) waitFor(want ...string) {
	s.t.Helper()
	s.until(fmt.Sprintf("the screen to show %q", want), func(v *vt) bool {
		screen := v.screen()
		for _, w := range want {
			if !strings.Contains(screen, w) {
				return false
			}
		}
		return true
	})
}

// untilPrinted waits until the main screen shows want
func (s *tty) untilPrinted(want string) {
	s.t.Helper()
	s.until(fmt.Sprintf("the main screen to show %q", want), func(v *vt) bool { return strings.Contains(v.printed.String(), want) })
}

// until waits for ok of the terminal, failing after ttyWait
func (s *tty) until(what string, ok func(v *vt) bool) {
	s.t.Helper()
	for deadline := time.Now().Add(ttyWait); ; time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		met := ok(s.vt)
		s.mu.Unlock()
		if met {
			return
		}
		if time.Now().After(deadline) {
			s.fatalf("waited %v for %s", ttyWait, what)
		}
	}
}

// exit waits for lw to exit and the terminal to show all it wrote, failing
// after ttyWait, and returns lw's status
func (s *tty) exit() int {
	s.t.Helper()
	timeout := time.After(ttyWait)
	for _, end := range []chan struct{}{s.done, s.read} {
		select {
		case <-end:
		case <-timeout:
			s.fatalf("lw did not exit in %v", ttyWait)
		}
	}
	return s.state.ExitCode()
}

// exitsRestored fails unless lw exits with status 0, the terminal back on
// its main screen with the cursor shown
func (s *tty) exitsRestored() {
	s.t.Helper()
	if code := s.exit(); code != 0 {
		s.fatalf("exit status %d", code)
	}
	s.mu.Lock()
	alt, hidden := s.vt.alt, s.vt.hidden
	s.mu.Unlock()
	if alt || hidden {
		s.fatalf("the terminal is left on the alternate screen %v, its cursor hidden %v", alt, hidden)
	}
}

// fatalf fails the test, showing the terminal
func (s *tty) fatalf(format string, args ...any) {
	s.t.Helper()
	s.mu.Lock()
	screen, printed := s.vt.screen(), s.vt.printed.String()
	s.mu.Unlock()
	s.t.Fatalf(format+"\nthe screen:\n%s\nprinted on the main screen:\n%s", append(args, screen, printed)...)
}

// vt is as much of a terminal as lw needs: the cells of the alternate
// screen, where lw draws, and the text it prints on the main screen
type vt struct {
	w, h    int
	cells   [][]rune
	x, y    int
	alt     bool // on the alternate screen
	hidden  bool // the cursor
	printed strings.Builder
	rest    []byte // a sequence or rune that a later write completes
}

func newVT(w, h int) *vt {
	v := &vt{w: w, h: h}
	v.erase(0, 0, w, h)
	return v
}

// screen is the alternate screen's rows, their trailing blanks trimmed
func (v *vt) screen() string {
	rows := make([]string, len(v.cells))
	for i, row := range v.cells {
		rows[i] = strings.TrimRight(string(row), " ")
	}
	return strings.Join(rows, "\n")
}

// row is the alternate screen's row y, its trailing blanks trimmed
func (v *vt) row(y int) string { return strings.TrimRight(string(v.cells[y]), " ") }

func (v *vt) write(p []byte) {
	b := append(v.rest, p...)
	for len(b) > 0 {
		n := v.step(b)
		if n == 0 {
			break
		}
		b = b[n:]
	}
	v.rest = append([]byte(nil), b...)
}

// step takes the character, control or sequence b starts with and returns
// its length, 0 while b holds only its start
func (v *vt) step(b []byte) int {
	switch c := b[0]; {
	case c == 0x1b:
		return v.escape(b)
	case c < 0x20 || c == 0x7f:
		v.control(c)
		return 1
	case !utf8.FullRune(b):
		return 0
	}
	r, n := utf8.DecodeRune(b)
	if !v.alt {
		v.printed.WriteRune(r)
		return n
	}
	v.cells[v.y][v.x] = r
	v.x = min(v.x+1, v.w-1) // auto-wrap is off: the last column takes the rest
	return n
}

func (v *vt) control(c byte) {
	switch c {
	case '\n':
		if !v.alt {
			v.printed.WriteByte('\n')
		}
		v.y = min(v.y+1, v.h-1)
	case '\r':
		v.x = 0
	case '\b':
		v.x = max(v.x-1, 0)
	}
}

func (v *vt) escape(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	switch b[1] {
	case '[':
		for i := 2; i < len(b); i++ {
			if b[i] >= 0x40 && b[i] <= 0x7e {
				v.csi(string(b[2:i]), b[i])
				return i + 1
			}
		}
		return 0
	case ']', 'P', '_', '^': // a string, ended by BEL or ST
		for i := 2; i < len(b); i++ {
			switch {
			case b[i] == 0x07:
				return i + 1
			case b[i] == 0x1b && i+1 < len(b) && b[i+1] == '\\':
				return i + 2
			}
		}
		return 0
	}
	return 2
}

func (v *vt) csi(params string, final byte) {
	if rest, ok := strings.CutPrefix(params, "?"); ok {
		for p := range strings.SplitSeq(rest, ";") {
			switch {
			case p == "1049" && final == 'h':
				v.alt, v.x, v.y = true, 0, 0
				v.erase(0, 0, v.w, v.h)
			case p == "1049" && final == 'l':
				v.alt = false
			case p == "25":
				v.hidden = final == 'l'
			}
		}
		return
	}
	ps := strings.Split(params, ";")
	n := func(i, def int) int {
		if i < len(ps) {
			if n, err := strconv.Atoi(ps[i]); err == nil && n > 0 {
				return n
			}
		}
		return def
	}
	switch final {
	case 'H', 'f':
		v.y, v.x = n(0, 1)-1, n(1, 1)-1
	case 'A':
		v.y -= n(0, 1)
	case 'B':
		v.y += n(0, 1)
	case 'C':
		v.x += n(0, 1)
	case 'D':
		v.x -= n(0, 1)
	case 'J':
		switch ps[0] {
		case "", "0":
			v.erase(v.x, v.y, v.w, v.y+1)
			v.erase(0, v.y+1, v.w, v.h)
		case "1":
			v.erase(0, 0, v.w, v.y)
			v.erase(0, v.y, v.x+1, v.y+1)
		default:
			v.erase(0, 0, v.w, v.h)
		}
	case 'K':
		switch ps[0] {
		case "", "0":
			v.erase(v.x, v.y, v.w, v.y+1)
		case "1":
			v.erase(0, v.y, v.x+1, v.y+1)
		default:
			v.erase(0, v.y, v.w, v.y+1)
		}
	}
	v.x, v.y = max(0, min(v.x, v.w-1)), max(0, min(v.y, v.h-1))
}

// erase blanks the cells from column x0 to x1 of rows y0 to y1, ends excluded
func (v *vt) erase(x0, y0, x1, y1 int) {
	if v.cells == nil {
		v.cells = make([][]rune, v.h)
		for y := range v.cells {
			v.cells[y] = make([]rune, v.w)
		}
	}
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			v.cells[y][x] = ' '
		}
	}
}
