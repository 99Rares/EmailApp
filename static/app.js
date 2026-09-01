function setLoadingSpinnerVisible(visible) {
  const overlay = document.getElementById("loadingOverlay");
  if (!overlay) {
    return;
  }
  overlay.classList.toggle("is-visible", visible);
  overlay.setAttribute("aria-hidden", String(!visible));
}

window.addEventListener("pageshow", () => {
  setLoadingSpinnerVisible(false);
});

function updateRuleFormRequirements(actionType) {
  const generatedEmail = document.getElementById("generated_email");
  const destinationEmail = document.getElementById("destination_email");

  if (actionType === "drop") {
    generatedEmail.required = true;
    destinationEmail.required = false;
  } else {
    generatedEmail.required = false;
    destinationEmail.required = true;
  }
}

function populateRuleForm(row) {
  document.querySelectorAll("#emailTable tbody tr").forEach((item) => {
    item.classList.remove("selected");
  });
  row.classList.add("selected");

  const actionType = row.dataset.actionType || "forward";
  document.getElementById("generated_email").value = row.dataset.generatedEmail || "";
  document.getElementById("app_name").value = row.dataset.serviceName || "";
  document.getElementById("action_type").value = actionType;

  const destination = row.dataset.destinationEmail || "";
  const destinationSelect = document.getElementById("destination_email");
  destinationSelect.value = actionType === "drop" ? "" : destination;
  updateRuleFormRequirements(actionType);
  document.getElementById("ruleForm").scrollIntoView({ behavior: "smooth", block: "start" });
}

document.addEventListener("DOMContentLoaded", () => {
  const actionType = document.getElementById("action_type");
  actionType.addEventListener("change", () => updateRuleFormRequirements(actionType.value));
  updateRuleFormRequirements(actionType.value);

  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", () => setLoadingSpinnerVisible(true));
  });

  document.querySelectorAll("#emailTable tbody tr").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("button, form, a, input, select, textarea")) {
        return;
      }
      populateRuleForm(row);
    });
  });
});
