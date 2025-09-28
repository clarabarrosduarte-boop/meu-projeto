const qs = (selector, scope = document) => scope.querySelector(selector);
const qsa = (selector, scope = document) => [...scope.querySelectorAll(selector)];

async function initShareButtons() {
  qsa('[data-share]').forEach((button) => {
    button.addEventListener('click', async () => {
      const link = button.getAttribute('data-share-url') || window.location.href;
      try {
        await navigator.clipboard.writeText(link);
        button.classList.add('shared');
        button.textContent = 'Link copiado! Bora compartilhar';
        setTimeout(() => button.classList.remove('shared'), 2000);
      } catch (error) {
        const fallback = prompt('Copie o link e mande para um amigo:', link);
        if (fallback !== null) {
          button.textContent = 'Link pronto pra mandar!';
        }
      }
    });
  });
}

async function initPlayerClip() {
  const container = qs('.video-detail');
  const player = qs('#player');
  if (!container || !player) {
    return;
  }
  const videoId = container.dataset.videoId;
  try {
    const response = await fetch(`/api/videos/${videoId}/clip`, { headers: { 'Accept': 'application/json' } });
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    const start = Number(data.start_time || 0);
    const end = Number(data.end_time ?? -1);
    player.addEventListener('loadedmetadata', () => {
      if (!Number.isNaN(start) && start > 0 && start < player.duration) {
        player.currentTime = start;
      }
    });
    if (!Number.isNaN(end) && end > 0) {
      player.addEventListener('timeupdate', () => {
        if (player.currentTime >= end) {
          player.pause();
        }
      });
    }
  } catch (error) {
    console.warn('Não foi possível carregar o recorte do vídeo.', error);
  }
}

function initEditorControls() {
  const form = qs('form[data-editor]');
  const player = qs('#editorPlayer');
  if (!form || !player) {
    return;
  }
  const startInput = qs('#' + form.querySelector('[name="start_time"]').id);
  const endInput = qs('#' + form.querySelector('[name="end_time"]').id);

  qsa('[data-mark="start"]', form).forEach((button) => {
    button.addEventListener('click', () => {
      startInput.value = player.currentTime.toFixed(1);
      button.blur();
    });
  });

  qsa('[data-mark="end"]', form).forEach((button) => {
    button.addEventListener('click', () => {
      endInput.value = player.currentTime.toFixed(1);
      button.blur();
    });
  });

  form.addEventListener('submit', () => {
    const start = parseFloat(startInput.value || '0');
    const end = parseFloat(endInput.value || '-1');
    if (!Number.isNaN(end) && end !== -1 && end <= start) {
      alert('O tempo final precisa ser maior que o inicial ou -1.');
    }
  });
}

function init() {
  initShareButtons();
  initPlayerClip();
  initEditorControls();
}

document.addEventListener('DOMContentLoaded', init);
