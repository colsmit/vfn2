#@category AgentToolchain

"""
Headless pre-script that enables the Decompiler Parameter ID analyzer so downstream
preprocessing can recover accurate function prototypes.
"""


def main():
    program = currentProgram
    if program is None:
        println("No active program; skipping parameter-id enablement.")
        return

    analysis_options = program.getOptions("Analysis")
    target = None
    if analysis_options:
        try:
            option_names = list(analysis_options.getOptionNames())
        except Exception:
            option_names = []
        for name in option_names:
            if "Decompiler Parameter ID" in name:
                target = name
                break

    if analysis_options and target:
        try:
            currently_enabled = analysis_options.getBoolean(target, False)
        except Exception:
            currently_enabled = False
        if not currently_enabled:
            try:
                analysis_options.setBoolean(target, True)
                println("Enabled analyzer option: %s" % target)
            except Exception as exc:
                println("Failed to enable analyzer %s: %s" % (target, exc))
        else:
            println("Analyzer already enabled: %s" % target)
    else:
        if analysis_options:
            println("Could not locate Decompiler Parameter ID analyzer option; available keys:")
            try:
                for name in option_names:
                    println("  - %s" % name)
            except Exception:
                pass
        else:
            println("No analysis options available on current program.")


if __name__ == "__main__":
    main()
