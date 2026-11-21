//! Shell completion scripts

pub const BASH_COMPLETION: &str = r#"#!/bin/bash
# Bash completion for vulnizard

_vulnizard() {
    local cur prev words cword
    if type _init_completion &>/dev/null; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local commands="sync update-products search stats info project app watch completions"
    local project_cmds="add list delete"
    local app_cmds="add list update delete"
    local watch_cmds="scan list status summary"

    # Get the command (first non-option argument after vulnizard)
    local cmd=""
    local subcmd=""
    local i
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            -*)
                continue
                ;;
            sync|update-products|search|stats|info|project|app|watch|completions)
                cmd="${words[i]}"
                # Look for subcommand
                for ((j=i+1; j < cword; j++)); do
                    case "${words[j]}" in
                        -*)
                            continue
                            ;;
                        add|list|delete|update|scan|status|summary|generate|projects|apps|cves)
                            subcmd="${words[j]}"
                            break
                            ;;
                    esac
                done
                break
                ;;
        esac
    done

    # Complete based on context
    case "$prev" in
        --project)
            local projects
            projects=$(vulnizard completions projects 2>/dev/null)
            COMPREPLY=($(compgen -W "$projects" -- "$cur"))
            return
            ;;
        --app)
            # Try to find --project value for context
            local proj=""
            for ((i=1; i < cword; i++)); do
                if [[ "${words[i]}" == "--project" && $((i+1)) -lt cword ]]; then
                    proj="${words[i+1]}"
                    break
                fi
            done
            local apps
            if [[ -n "$proj" ]]; then
                apps=$(vulnizard completions apps --project "$proj" 2>/dev/null)
            else
                apps=$(vulnizard completions apps 2>/dev/null)
            fi
            COMPREPLY=($(compgen -W "$apps" -- "$cur"))
            return
            ;;
        --status)
            COMPREPLY=($(compgen -W "untreated treated accepted not_applicable" -- "$cur"))
            return
            ;;
        --sort)
            COMPREPLY=($(compgen -W "cvss epss published modified" -- "$cur"))
            return
            ;;
        --format|-f)
            COMPREPLY=($(compgen -W "table json" -- "$cur"))
            return
            ;;
        --ecosystem)
            COMPREPLY=($(compgen -W "npm PyPI Maven Go crates.io NuGet" -- "$cur"))
            return
            ;;
        --min-cvss)
            COMPREPLY=($(compgen -W "0 4.0 7.0 9.0" -- "$cur"))
            return
            ;;
        --min-epss)
            COMPREPLY=($(compgen -W "0.001 0.01 0.1 0.5" -- "$cur"))
            return
            ;;
        --config|-c|--db)
            _filedir
            return
            ;;
        vulnizard)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            return
            ;;
    esac

    # Complete subcommands and options based on command
    case "$cmd" in
        "")
            COMPREPLY=($(compgen -W "$commands --help --version -h -V" -- "$cur"))
            ;;
        search)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--min-cvss --min-epss --kev --vendor --product --version --has-exploit --ecosystem --package --sort --limit -l --format -f --help -h" -- "$cur"))
            else
                # Suggest CVE ID pattern or product names
                COMPREPLY=($(compgen -W "CVE-" -- "$cur"))
            fi
            ;;
        info)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
            else
                # Could suggest CVE IDs from database
                COMPREPLY=($(compgen -W "CVE-" -- "$cur"))
            fi
            ;;
        sync)
            COMPREPLY=($(compgen -W "--months --source --full --help -h" -- "$cur"))
            ;;
        stats|update-products)
            COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
            ;;
        project)
            case "$subcmd" in
                "")
                    COMPREPLY=($(compgen -W "$project_cmds --help -h" -- "$cur"))
                    ;;
                add)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--description --help -h" -- "$cur"))
                    fi
                    ;;
                delete)
                    if [[ "$cur" != -* ]]; then
                        local projects
                        projects=$(vulnizard completions projects 2>/dev/null)
                        COMPREPLY=($(compgen -W "$projects" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
                    fi
                    ;;
                list)
                    COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
                    ;;
            esac
            ;;
        app)
            case "$subcmd" in
                "")
                    COMPREPLY=($(compgen -W "$app_cmds --help -h" -- "$cur"))
                    ;;
                add)
                    COMPREPLY=($(compgen -W "--project --version --vendor --ecosystem --help -h" -- "$cur"))
                    ;;
                list)
                    COMPREPLY=($(compgen -W "--project --help -h" -- "$cur"))
                    ;;
                update)
                    COMPREPLY=($(compgen -W "--project --version --current-version --help -h" -- "$cur"))
                    ;;
                delete)
                    COMPREPLY=($(compgen -W "--project --version --help -h" -- "$cur"))
                    ;;
            esac
            ;;
        watch)
            case "$subcmd" in
                "")
                    COMPREPLY=($(compgen -W "$watch_cmds --help -h" -- "$cur"))
                    ;;
                scan)
                    COMPREPLY=($(compgen -W "--project --app --help -h" -- "$cur"))
                    ;;
                list)
                    COMPREPLY=($(compgen -W "--project --app --status --format -f --help -h" -- "$cur"))
                    ;;
                status)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--app --project --status --notes --help -h" -- "$cur"))
                    else
                        # Suggest CVE IDs from watchlist
                        local cves
                        cves=$(vulnizard completions cves 2>/dev/null)
                        COMPREPLY=($(compgen -W "$cves" -- "$cur"))
                    fi
                    ;;
                summary)
                    COMPREPLY=($(compgen -W "--project --help -h" -- "$cur"))
                    ;;
            esac
            ;;
        completions)
            case "$subcmd" in
                "")
                    COMPREPLY=($(compgen -W "generate projects apps cves --help -h" -- "$cur"))
                    ;;
                generate)
                    COMPREPLY=($(compgen -W "bash zsh fish powershell elvish" -- "$cur"))
                    ;;
                apps)
                    COMPREPLY=($(compgen -W "--project --help -h" -- "$cur"))
                    ;;
                cves)
                    COMPREPLY=($(compgen -W "--project --app --help -h" -- "$cur"))
                    ;;
            esac
            ;;
    esac
}

complete -F _vulnizard vulnizard
"#;

pub const ZSH_COMPLETION: &str = r#"#compdef vulnizard

# Zsh completion for vulnizard

# Dynamic completion functions
_vulnizard_projects() {
    local projects
    projects=(${(f)"$(vulnizard completions projects 2>/dev/null)"})
    _describe -t projects 'project' projects
}

_vulnizard_apps() {
    local apps project
    # Check if --project was specified
    if (( ${+opt_args[--project]} )); then
        project="${opt_args[--project]}"
        apps=(${(f)"$(vulnizard completions apps --project "$project" 2>/dev/null)"})
    else
        apps=(${(f)"$(vulnizard completions apps 2>/dev/null)"})
    fi
    _describe -t apps 'application' apps
}

_vulnizard_cves() {
    local cves project app
    local -a cmd_args
    if (( ${+opt_args[--project]} )); then
        cmd_args+=(--project "${opt_args[--project]}")
    fi
    if (( ${+opt_args[--app]} )); then
        cmd_args+=(--app "${opt_args[--app]}")
    fi
    cves=(${(f)"$(vulnizard completions cves ${cmd_args[@]} 2>/dev/null)"})
    _describe -t cves 'CVE ID' cves
}

_vulnizard() {
    local context state state_descr line
    typeset -A opt_args

    local -a global_opts
    global_opts=(
        '(-c --config)'{-c,--config}'[Path to config file]:config file:_files'
        '--db[Database path]:database file:_files'
        '(-v --verbose)'{-v,--verbose}'[Verbose output]'
        '(-h --help)'{-h,--help}'[Print help]'
        '(-V --version)'{-V,--version}'[Print version]'
    )

    _arguments -C \
        $global_opts \
        '1:command:->command' \
        '*::args:->args'

    case $state in
        command)
            local -a commands
            commands=(
                'sync:Synchronize CVE data from all sources'
                'update-products:Extract affected products from descriptions'
                'search:Search CVEs'
                'stats:Show database statistics'
                'info:Show details for a specific CVE'
                'project:Project management'
                'app:Application management'
                'watch:Watchlist management'
                'completions:Shell completions'
            )
            _describe -t commands 'command' commands
            ;;
        args)
            case $words[1] in
                sync)
                    _arguments \
                        $global_opts \
                        '--months[History months to sync]:months:(1 3 6 12 24)' \
                        '--source[Only sync specific source]:source:(nvd cisa_kev epss exploitdb metasploit osv)' \
                        '--full[Force full sync instead of incremental]'
                    ;;
                search)
                    _arguments \
                        $global_opts \
                        '1:query:' \
                        '--min-cvss[Minimum CVSS score]:score:(0 4.0 7.0 9.0)' \
                        '--min-epss[Minimum EPSS score]:score:(0.001 0.01 0.1 0.5)' \
                        '--kev[Only show KEV vulnerabilities]' \
                        '--vendor[Filter by vendor]:vendor:' \
                        '--product[Filter by product]:product:' \
                        '--version[Filter by version]:version:' \
                        '--has-exploit[Only show CVEs with public exploits]' \
                        '--ecosystem[Filter by ecosystem]:ecosystem:(npm PyPI Maven Go crates.io NuGet RubyGems)' \
                        '--package[Filter by package name]:package:' \
                        '--sort[Sort by]:field:(cvss epss published modified)' \
                        '(-l --limit)'{-l,--limit}'[Maximum results]:limit:(10 20 50 100)' \
                        '(-f --format)'{-f,--format}'[Output format]:format:(table json)'
                    ;;
                stats)
                    _arguments $global_opts
                    ;;
                info)
                    _arguments \
                        $global_opts \
                        '1:CVE ID:(CVE-)'
                    ;;
                update-products)
                    _arguments $global_opts
                    ;;
                project)
                    _arguments -C \
                        $global_opts \
                        '1:subcommand:->subcmd' \
                        '*::args:->subargs'
                    case $state in
                        subcmd)
                            local -a subcmds
                            subcmds=(
                                'add:Add a new project'
                                'list:List all projects'
                                'delete:Delete a project'
                            )
                            _describe -t subcmds 'subcommand' subcmds
                            ;;
                        subargs)
                            case $words[1] in
                                add)
                                    _arguments \
                                        $global_opts \
                                        '1:project name:' \
                                        '--description[Project description]:description:'
                                    ;;
                                list)
                                    _arguments $global_opts
                                    ;;
                                delete)
                                    _arguments \
                                        $global_opts \
                                        '1:project name:_vulnizard_projects'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                app)
                    _arguments -C \
                        $global_opts \
                        '1:subcommand:->subcmd' \
                        '*::args:->subargs'
                    case $state in
                        subcmd)
                            local -a subcmds
                            subcmds=(
                                'add:Add an application to a project'
                                'list:List applications in a project'
                                'update:Update application version'
                                'delete:Delete an application'
                            )
                            _describe -t subcmds 'subcommand' subcmds
                            ;;
                        subargs)
                            case $words[1] in
                                add)
                                    _arguments \
                                        $global_opts \
                                        '1:application name:' \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--version[Application version]:version:' \
                                        '--vendor[Vendor name]:vendor:' \
                                        '--ecosystem[Package ecosystem]:ecosystem:(npm PyPI Maven Go crates.io NuGet RubyGems)'
                                    ;;
                                list)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects'
                                    ;;
                                update)
                                    _arguments \
                                        $global_opts \
                                        '1:application name:_vulnizard_apps' \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--version[New version]:version:' \
                                        '--current-version[Current version]:version:'
                                    ;;
                                delete)
                                    _arguments \
                                        $global_opts \
                                        '1:application name:_vulnizard_apps' \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--version[Version]:version:'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                watch)
                    _arguments -C \
                        $global_opts \
                        '1:subcommand:->subcmd' \
                        '*::args:->subargs'
                    case $state in
                        subcmd)
                            local -a subcmds
                            subcmds=(
                                'scan:Scan applications for CVEs'
                                'list:List watchlist entries'
                                'status:Update CVE status for an application'
                                'summary:Show watchlist summary'
                            )
                            _describe -t subcmds 'subcommand' subcmds
                            ;;
                        subargs)
                            case $words[1] in
                                scan)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--app[Application name]:app:_vulnizard_apps'
                                    ;;
                                list)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--app[Application name]:app:_vulnizard_apps' \
                                        '--status[Filter by status]:status:(untreated treated accepted not_applicable)' \
                                        '(-f --format)'{-f,--format}'[Output format]:format:(table json)'
                                    ;;
                                status)
                                    _arguments \
                                        $global_opts \
                                        '1:CVE ID:_vulnizard_cves' \
                                        '--app[Application name]:app:_vulnizard_apps' \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--status[New status]:status:(treated accepted not_applicable untreated)' \
                                        '--notes[Notes]:notes:'
                                    ;;
                                summary)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                completions)
                    _arguments -C \
                        $global_opts \
                        '1:subcommand:->subcmd' \
                        '*::args:->subargs'
                    case $state in
                        subcmd)
                            local -a subcmds
                            subcmds=(
                                'generate:Generate shell completions'
                                'projects:List projects'
                                'apps:List applications'
                                'cves:List CVE IDs in watchlist'
                            )
                            _describe -t subcmds 'subcommand' subcmds
                            ;;
                        subargs)
                            case $words[1] in
                                generate)
                                    _arguments \
                                        $global_opts \
                                        '1:shell:(bash zsh fish powershell elvish)'
                                    ;;
                                apps)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects'
                                    ;;
                                cves)
                                    _arguments \
                                        $global_opts \
                                        '--project[Project name]:project:_vulnizard_projects' \
                                        '--app[Application name]:app:_vulnizard_apps'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

_vulnizard "$@"
"#;
