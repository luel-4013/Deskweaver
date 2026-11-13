package cli

import (
	"context"
	"errors"
	"strings"

	"github.com/charmbracelet/huh"
)

func pickDoctorTargetHuh(ctx context.Context, s *streams) (doctorChoice, error) {
	choice := "current"
	field := huh.NewSelect[string]().
		Title("Which build target should doctor check?").
		Description("Host probes run on this machine. Cross-target results are labeled and still require verification on the real target OS.").
		Options(
			huh.NewOption("This host (recommended)", "current"),
			huh.NewOption("Linux · Ubuntu 22.04", "linux|ubuntu-22.04"),
			huh.NewOption("Linux · Debian 12", "linux|debian-12"),
			huh.NewOption("Linux · Fedora 40", "linux|fedora-40"),
			huh.NewOption("Linux · Arch Linux", "linux|arch"),
			huh.NewOption("Windows 10/11", "windows|"),
			huh.NewOption("macOS", "macos|"),
		).
		Value(&choice)

	theme := huh.ThemeCharm()
	if s.noColor {
		theme = huh.ThemeBase()
	}
	form := huh.NewForm(
		huh.NewGroup(field).Title("Host doctor"),
	).WithInput(s.in).WithOutput(s.out).WithTheme(theme).WithWidth(86)
	if err := form.RunWithContext(ctx); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return doctorChoice{}, context.Canceled
		}
		return doctorChoice{}, err
	}
	if choice == "current" {
		return doctorChoice{}, nil
	}
	osName, distro, _ := strings.Cut(choice, "|")
	return doctorChoice{os: osName, distro: distro}, nil
}
