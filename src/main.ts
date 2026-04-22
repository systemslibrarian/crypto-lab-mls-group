import './style.css';
import { renderApp } from './app';

function setupThemeToggle(button: HTMLButtonElement): void {
  const root = document.documentElement;

  const refresh = () => {
    const current = root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    button.textContent = current === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', current === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    button.onclick = () => {
      root.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      refresh();
    };
  };

  refresh();
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing app root');
}

const { themeButton } = renderApp(app);
setupThemeToggle(themeButton);
