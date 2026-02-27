/* PyOS Web Terminal — command input and history. */

const output = document.getElementById("output");
const input = document.getElementById("command");
const history = [];
let historyIndex = -1;

function appendOutput(text) {
    const pre = document.createElement("pre");
    pre.textContent = text;
    output.appendChild(pre);
    output.scrollTop = output.scrollHeight;
}

async function executeCommand(command) {
    appendOutput("PyOS> " + command);

    try {
        const response = await fetch("/api/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command }),
        });

        const data = await response.json();

        if (data.output) {
            appendOutput(data.output);
        }

        if (data.halted) {
            input.disabled = true;
            input.placeholder = "System halted.";
        }
    } catch (err) {
        appendOutput("Error: " + err.message);
    }
}

input.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        const command = input.value.trim();
        if (command) {
            history.push(command);
            historyIndex = history.length;
            executeCommand(command);
        }
        input.value = "";
    } else if (event.key === "ArrowUp") {
        event.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            input.value = history[historyIndex];
        }
    } else if (event.key === "ArrowDown") {
        event.preventDefault();
        if (historyIndex < history.length - 1) {
            historyIndex++;
            input.value = history[historyIndex];
        } else {
            historyIndex = history.length;
            input.value = "";
        }
    }
});
