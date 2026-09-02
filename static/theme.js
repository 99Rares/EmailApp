(function () {
  const themeStorageKey = "emailapp-theme";
  const styleStorageKey = "emailapp-ui-style";
  let theme = "dark";
  let uiStyle = "liquid";

  try {
    const savedTheme = localStorage.getItem(themeStorageKey);
    const savedStyle = localStorage.getItem(styleStorageKey);
    if (savedTheme === "light" || savedTheme === "dark") {
      theme = savedTheme;
    }
    if (savedStyle === "liquid" || savedStyle === "default") {
      uiStyle = savedStyle;
    }
  } catch (error) {
    // Keep the defaults when browser storage is unavailable.
  }

  document.documentElement.setAttribute("data-bs-theme", theme);
  document.documentElement.setAttribute("data-ui-style", uiStyle);

  function updateControls() {
    const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    const isLiquid = document.documentElement.getAttribute("data-ui-style") === "liquid";

    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} mode`);
      button.querySelector(".theme-label").textContent = isDark ? "Light mode" : "Dark mode";
      button.querySelector("i").className = isDark ? "bi bi-sun-fill" : "bi bi-moon-stars-fill";
    });

    document.querySelectorAll(".style-toggle").forEach((button) => {
      button.setAttribute("aria-label", `Switch to ${isLiquid ? "default" : "liquid glass"} appearance`);
      button.querySelector(".style-label").textContent = isLiquid ? "Default style" : "Liquid glass";
      button.querySelector("i").className = isLiquid ? "bi bi-square" : "bi bi-droplet-fill";
      button.setAttribute("aria-pressed", String(isLiquid));
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
          localStorage.setItem(themeStorageKey, nextTheme);
        } catch (error) {
          // The theme still works for this page when storage is unavailable.
        }
        updateControls();
      });
    });

    document.querySelectorAll(".style-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const currentStyle = document.documentElement.getAttribute("data-ui-style");
        const nextStyle = currentStyle === "liquid" ? "default" : "liquid";
        document.documentElement.setAttribute("data-ui-style", nextStyle);
        try {
          localStorage.setItem(styleStorageKey, nextStyle);
        } catch (error) {
          // The appearance still works for this page when storage is unavailable.
        }
        updateControls();
      });
    });
  });
})();
