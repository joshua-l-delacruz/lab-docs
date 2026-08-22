const quoteForm = document.querySelector("#quote-form");
const packageField = document.querySelector("#quote-package");
const formStatus = document.querySelector("#form-status");

document.querySelectorAll("[data-package]").forEach((link) => {
  link.addEventListener("click", () => {
    packageField.value = link.dataset.package;
  });
});

quoteForm.addEventListener("submit", (event) => {
  event.preventDefault();

  if (!quoteForm.reportValidity()) {
    return;
  }

  const data = new FormData(quoteForm);
  const projectPackage = data.get("package");
  const subject = `Project quote request — ${projectPackage}`;
  const body = [
    "Hello Joshua,",
    "",
    "I would like to request a written project quote.",
    "",
    `Name: ${data.get("name")}`,
    `Email: ${data.get("email")}`,
    `Package: ${projectPackage}`,
    `Preferred start: ${data.get("start") || "Flexible"}`,
    "",
    "Project details:",
    data.get("details"),
    "",
    "I understand that the final written scope will define deliverables, turnaround time, revision limits, and that a 30–50% deposit is required before substantial work begins."
  ].join("\n");

  formStatus.textContent = "Opening your email app with the request details…";
  window.location.href = `mailto:josh.delacruz19@gmail.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
});
