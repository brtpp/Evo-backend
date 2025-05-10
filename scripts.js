// 

// ← change this to your deployed backend URL:
const apiURL = "https://evo13-fixed-3.onrender.com/infer";

async function sendMessage() {
  const inputEl = document.getElementById("userInput");
  const msg = inputEl.value.trim();
  if (!msg) return;

  // show the user’s message
  const log = document.getElementById("chatLog");
  const userMsg = document.createElement("div");
  userMsg.className = "message user";
  userMsg.innerText = "You: " + msg;
  log.appendChild(userMsg);

  inputEl.value = "";  // clear input

  // build a simple behavior object (you can adjust or remove if not needed)
  const behavior = {
    avgSpeed: 150,
    backspaceCount: 2,
    hoverTime: 3
  };

  try {
    const res = await fetch(apiURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: msg,
        user_id: "anon",
        tier: "free",
        behavior: behavior
      })
    });
    if (!res.ok) throw new Error(res.status + " " + res.statusText);

    const data = await res.json();
    const botMsg = document.createElement("div");
    botMsg.className = "message bot";
    botMsg.innerText = "Evo13: " + data.response;
    log.appendChild(botMsg);
    log.scrollTop = log.scrollHeight;

  } catch (err) {
    const errMsg = document.createElement("div");
    errMsg.className = "message error";
    errMsg.innerText = "Error: " + err.message;
    log.appendChild(errMsg);
    log.scrollTop = log.scrollHeight;
  }
}
