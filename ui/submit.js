/**
 * MAVERICK User Submission Portal - Client Controller
 * Handles reporter .eml uploads and Case ID confirmation.
 */

(function () {
  'use strict';

  let selectedFile = null;

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const dropzonePrompt = document.getElementById('dropzone-prompt');
  const fileLoadedBanner = document.getElementById('file-loaded-banner');
  const selectedFileName = document.getElementById('selected-file-name');
  const selectedFileSize = document.getElementById('selected-file-size');
  const clearFileBtn = document.getElementById('clear-file-btn');
  const submitBtn = document.getElementById('submit-btn');

  const submissionCard = document.getElementById('submission-card');
  const loadingCard = document.getElementById('loading-card');
  const confirmationCard = document.getElementById('confirmation-card');
  const confirmedCaseId = document.getElementById('confirmed-case-id');
  const copyTrackingBtn = document.getElementById('copy-tracking-btn');
  const submitAnotherBtn = document.getElementById('submit-another-btn');

  function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  function updateFileSelection(file) {
    selectedFile = file;
    if (file) {
      selectedFileName.textContent = file.name;
      selectedFileSize.textContent = formatBytes(file.size);
      dropzonePrompt.style.display = 'none';
      fileLoadedBanner.style.display = 'flex';
      submitBtn.disabled = false;
    } else {
      selectedFileName.textContent = '';
      selectedFileSize.textContent = '';
      fileLoadedBanner.style.display = 'none';
      dropzonePrompt.style.display = 'flex';
      submitBtn.disabled = true;
      fileInput.value = '';
    }
  }

  browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener('click', () => {
    if (!selectedFile) {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      updateFileSelection(e.target.files[0]);
    }
  });

  clearFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    updateFileSelection(null);
  });

  ['dragenter', 'dragover'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt.files && dt.files.length > 0) {
      updateFileSelection(dt.files[0]);
    }
  });

  submitBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    submitBtn.disabled = true;
    submissionCard.style.display = 'none';
    loadingCard.style.display = 'block';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/api/submissions', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errDetail = 'Failed to submit email';
        try {
          const errData = await response.json();
          errDetail = errData.detail || errDetail;
        } catch (_) {}
        throw new Error(errDetail);
      }

      const data = await response.json();
      confirmedCaseId.textContent = data.case_id || 'MAV-UNKNOWN';

      loadingCard.style.display = 'none';
      confirmationCard.style.display = 'block';
    } catch (err) {
      loadingCard.style.display = 'none';
      submissionCard.style.display = 'block';
      submitBtn.disabled = false;
      alert(`Submission Error: ${err.message}`);
    }
  });

  copyTrackingBtn.addEventListener('click', () => {
    const caseId = confirmedCaseId.textContent;
    if (caseId) {
      navigator.clipboard.writeText(caseId).then(() => {
        const orig = copyTrackingBtn.textContent;
        copyTrackingBtn.textContent = '✓ Copied!';
        setTimeout(() => {
          copyTrackingBtn.textContent = orig;
        }, 2000);
      });
    }
  });

  submitAnotherBtn.addEventListener('click', () => {
    updateFileSelection(null);
    confirmationCard.style.display = 'none';
    submissionCard.style.display = 'block';
  });
})();
