"""Learning commands -- the built-in interactive tutorials."""

from py_os.shell.base import ShellBase
from py_os.tutorials import TutorialRunner


class LearnCommands(ShellBase):
    """Shell commands for the built-in interactive tutorials."""

    def _cmd_learn(self, args: list[str]) -> str:
        """Run an interactive tutorial lesson."""
        runner = TutorialRunner(self._kernel)

        if not args:
            lessons = runner.list_lessons()
            lines = ["Available lessons:"]
            lines.extend(f"  {name}" for name in lessons)
            lines.append("")
            lines.append("Usage: learn <lesson> or learn all")
            return "\n".join(lines)

        if args[0] == "all":
            return runner.run_all()

        try:
            return runner.run(args[0])
        except KeyError:
            return f"Error: unknown lesson '{args[0]}'. Run 'learn' to see available lessons."

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (("learn", _cmd_learn),)
