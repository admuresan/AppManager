"""
Admin terminal execution API route.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os
import subprocess

from flask import current_app, jsonify, request
from flask_login import login_required

from ..blueprint import bp


@bp.route("/api/terminal/execute", methods=["POST"])
@login_required
def execute_terminal_command():
    """Execute a command in the server terminal."""
    try:
        data = request.get_json()
        command = (data.get("command", "") if data else "").strip()
        current_dir = data.get("cwd", os.path.expanduser("~")) if data else os.path.expanduser("~")

        if not command:
            return jsonify({"error": "No command provided"}), 400

        # Resolve current directory
        if current_dir == "~":
            working_dir = os.path.expanduser("~")
        elif os.path.isabs(current_dir):
            working_dir = current_dir
        else:
            working_dir = os.path.join(os.path.expanduser("~"), current_dir)

        working_dir = os.path.normpath(os.path.abspath(working_dir))

        # Security: Ensure working directory is in safe locations
        safe_directories = [
            os.path.expanduser("~"),
            "/opt/appmanager",
            "/tmp",
        ]

        dir_allowed = False
        for safe_dir in safe_directories:
            safe_dir_abs = os.path.abspath(safe_dir)
            if working_dir.startswith(safe_dir_abs + os.sep) or working_dir == safe_dir_abs:
                dir_allowed = True
                break
            if safe_dir_abs.startswith(working_dir + os.sep) and working_dir != os.sep and working_dir != "":
                dir_allowed = True
                break

        if not dir_allowed:
            working_dir = os.path.expanduser("~")

        # Handle cd command specially to update working directory
        new_working_dir = working_dir
        if command.startswith("cd ") or command == "cd":
            if command == "cd":
                new_working_dir = os.path.expanduser("~")
                working_dir = new_working_dir
                home = os.path.expanduser("~")
                display_dir = "~" if working_dir == home else working_dir
                return jsonify({"success": True, "output": "", "exit_code": 0, "command": command, "cwd": display_dir})

            cd_target = command[3:].strip() if command.startswith("cd ") else ""
            if not cd_target:
                new_working_dir = os.path.expanduser("~")
                working_dir = new_working_dir
                home = os.path.expanduser("~")
                display_dir = "~" if working_dir == home else working_dir
                return jsonify({"success": True, "output": "", "exit_code": 0, "command": command, "cwd": display_dir})
            if cd_target == "-":
                new_working_dir = os.path.expanduser("~")
                working_dir = new_working_dir
                home = os.path.expanduser("~")
                display_dir = "~" if working_dir == home else working_dir
                return jsonify({"success": True, "output": "", "exit_code": 0, "command": command, "cwd": display_dir})

            if os.path.isabs(cd_target):
                target_dir = cd_target
            else:
                target_dir = os.path.join(working_dir, cd_target)

            target_dir = os.path.normpath(os.path.abspath(target_dir))

            target_allowed = False
            for safe_dir in safe_directories:
                safe_dir_abs = os.path.abspath(safe_dir)
                if target_dir.startswith(safe_dir_abs + os.sep) or target_dir == safe_dir_abs:
                    target_allowed = True
                    break
                if safe_dir_abs.startswith(target_dir + os.sep) and target_dir != os.sep and target_dir != "":
                    target_allowed = True
                    break

            if target_allowed and os.path.isdir(target_dir):
                new_working_dir = target_dir
                working_dir = new_working_dir
                home = os.path.expanduser("~")
                if working_dir == home:
                    display_dir = "~"
                elif working_dir.startswith(home + os.sep):
                    display_dir = "~" + working_dir[len(home) :]
                else:
                    display_dir = working_dir
                return jsonify({"success": True, "output": "", "exit_code": 0, "command": command, "cwd": display_dir})

            home = os.path.expanduser("~")
            if working_dir == home:
                display_dir = "~"
            elif working_dir.startswith(home + os.sep):
                display_dir = "~" + working_dir[len(home) :]
            else:
                display_dir = working_dir

            if not os.path.isdir(target_dir):
                return jsonify({"success": False, "error": f"cd: no such file or directory: {cd_target}", "exit_code": 1, "command": command, "cwd": display_dir})

            return jsonify({"success": False, "error": f"cd: permission denied: {cd_target}", "exit_code": 1, "command": command, "cwd": display_dir})

        working_dir = new_working_dir

        # Security: Whitelist of allowed commands/patterns
        allowed_patterns = [
            r"^ls\s",
            r"^ls$",
            r"^cd\s",
            r"^cd$",
            r"^pwd$",
            r"^cat\s",
            r"^head\s",
            r"^tail\s",
            r"^grep\s",
            r"^find\s",
            r"^ps\s",
            r"^ps$",
            r"^df\s",
            r"^df$",
            r"^du\s",
            r"^free\s",
            r"^free$",
            r"^uptime$",
            r"^whoami$",
            r"^uname\s",
            r"^uname$",
            r"^systemctl\s",
            r"^journalctl\s",
            r"^netstat\s",
            r"^ss\s",
            r"^sudo\s",
            r"^echo\s",
            r"^echo$",
            r"^date$",
            r"^hostname$",
            r"^ip\s",
            r"^ifconfig\s",
            r"^curl\s",
            r"^wget\s",
            r"^git\s",
            r"^python3\s",
            r"^python\s",
            r"^pip\s",
            r"^npm\s",
            r"^node\s",
            r"^docker\s",
            r"^docker-compose\s",
            r"^nginx\s",
            r"^certbot\s",
            r"^ufw\s",
            r"^iptables\s",
            r"^history$",
            r"^env$",
            r"^export\s",
            r"^source\s",
            r"^\.\s",
            r"^mkdir\s",
            r"^rmdir\s",
            r"^touch\s",
            r"^chmod\s",
            r"^chown\s",
            r"^cp\s",
            r"^mv\s",
            r"^rm\s",
            r"^tar\s",
            r"^zip\s",
            r"^unzip\s",
            r"^gzip\s",
            r"^gunzip\s",
            r"^less\s",
            r"^more\s",
            r"^nano\s",
            r"^vim\s",
            r"^vi\s",
            r"^wc\s",
            r"^wc$",
            r"^sort\s",
            r"^uniq\s",
            r"^diff\s",
            r"^which\s",
            r"^whereis\s",
            r"^man\s",
            r"^help$",
            r"^clear$",
            r"^bash\s",
            r"^sh\s",
            r"^\.\/",
        ]

        blocked_patterns = [
            r"rm\s+-rf\s+/",
            r"rm\s+-rf\s+/\s",
            r"^dd\s",
            r"^mkfs\s",
            r"^fdisk\s",
            r"^shutdown\s",
            r"^reboot\s",
            r"^halt\s",
            r"^poweroff\s",
            r"^>.*dev/",
            r"^rm\s+.*\.\.\.*\/",
        ]

        import re

        for pattern in blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return jsonify({"error": f"Command blocked for security: {command}"}), 403

        command_allowed = False
        for pattern in allowed_patterns:
            if re.match(pattern, command, re.IGNORECASE):
                command_allowed = True
                break

        script_patterns = [
            r"^(bash|sh)\s+.*\.sh",
            r"^\.\/.*\.sh",
            r"^bash\s+.*",
            r"^sh\s+.*",
        ]

        is_script_execution = any(re.match(pattern, command, re.IGNORECASE) for pattern in script_patterns)

        if is_script_execution:
            script_path = None
            if re.match(r"^(bash|sh)\s+(.+)", command, re.IGNORECASE):
                match = re.match(r"^(bash|sh)\s+(.+)", command, re.IGNORECASE)
                script_path = match.group(2).strip().split()[0]
            elif re.match(r"^\.\/(.+)", command):
                match = re.match(r"^\.\/(.+)", command)
                script_path = match.group(1).strip().split()[0]

            if script_path:
                safe_directories = [os.path.expanduser("~"), "/opt/appmanager", "/tmp"]

                if not os.path.isabs(script_path):
                    script_path = os.path.join(os.path.expanduser("~"), script_path)

                script_path = os.path.normpath(script_path)
                script_path_abs = os.path.abspath(script_path)

                script_allowed = False
                for safe_dir in safe_directories:
                    safe_dir_abs = os.path.abspath(safe_dir)
                    if script_path_abs.startswith(safe_dir_abs + os.sep) or script_path_abs == safe_dir_abs:
                        script_allowed = True
                        break

                if not script_allowed:
                    return jsonify(
                        {
                            "error": f"Script execution not allowed: {script_path}",
                            "hint": f"Scripts must be in one of these directories: {', '.join(safe_directories)}",
                        }
                    ), 403

                if not os.path.exists(script_path_abs):
                    return jsonify({"error": f"Script not found: {script_path}"}), 404

                command_allowed = True

        if not command_allowed:
            if re.match(r"^[a-zA-Z0-9_-]+$", command):
                current_app.logger.warning(f"Unknown single-word command executed: {command}")
                command_allowed = True

        if not command_allowed:
            home = os.path.expanduser("~")
            if working_dir == home:
                display_dir = "~"
            elif working_dir.startswith(home + os.sep):
                display_dir = "~" + working_dir[len(home) :]
            else:
                display_dir = working_dir
            return jsonify({"error": f"Command not allowed: {command}", "hint": "Only whitelisted commands are allowed for security. Contact admin to add new commands.", "cwd": display_dir}), 403

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=working_dir,
                env=dict(os.environ, **{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}),
            )

            output = result.stdout
            if result.stderr:
                output += f"\n{result.stderr}"

            home = os.path.expanduser("~")
            if working_dir == home:
                display_dir = "~"
            elif working_dir.startswith(home + os.sep):
                display_dir = "~" + working_dir[len(home) :]
            else:
                display_dir = working_dir

            return jsonify({"success": True, "output": output, "exit_code": result.returncode, "command": command, "cwd": display_dir})
        except subprocess.TimeoutExpired:
            home = os.path.expanduser("~")
            if working_dir == home:
                display_dir = "~"
            elif working_dir.startswith(home + os.sep):
                display_dir = "~" + working_dir[len(home) :]
            else:
                display_dir = working_dir
            return jsonify({"error": "Command timed out after 30 seconds", "command": command, "cwd": display_dir}), 408
        except Exception as e:
            home = os.path.expanduser("~")
            if working_dir == home:
                display_dir = "~"
            elif working_dir.startswith(home + os.sep):
                display_dir = "~" + working_dir[len(home) :]
            else:
                display_dir = working_dir
            return jsonify({"error": f"Error executing command: {str(e)}", "command": command, "cwd": display_dir}), 500

    except Exception as e:
        current_app.logger.error(f"Error in execute_terminal_command: {str(e)}", exc_info=True)
        try:
            data = request.get_json()
            current_dir = data.get("cwd", os.path.expanduser("~")) if data else os.path.expanduser("~")
            display_dir = "~" if current_dir == "~" else current_dir
        except Exception:
            display_dir = "~"
        return jsonify({"error": f"Server error: {str(e)}", "cwd": display_dir}), 500

