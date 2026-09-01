(function () {
  const storageKey = "emailapp-theme";
  let theme = "dark";

  try {
    const savedTheme = localStorage.getItem(storageKey);
    if (savedTheme === "light" || savedTheme === "dark") {
      theme = savedTheme;
    }
  } catch (error) {
    // Keep the dark default when browser storage is unavailable.
  }

  document.documentElement.setAttribute("data-bs-theme", theme);

  function updateControls() {
    const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} mode`);
      button.querySelector(".theme-label").textContent = isDark ? "Light mode" : "Dark mode";
      const icon = button.querySelector("i");
      icon.className = isDark ? "bi bi-sun-fill" : "bi bi-moon-stars-fill";
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    updateControls();
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-bs-theme");
        const nextTheme = currentTheme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-bs-theme", nextTheme);
        try {
          localStorage.setItem(storageKey, nextTheme);
        } catch (error) {
          // The theme still works for this page when storage is unavailable.
        }
        updateControls();
      });
    });
  });
})();
