/**
 * Using browser microphone permissions
 */

function micInit() {
  console.log('micInit: start');

  // Wait for DOM to load
  document.addEventListener('DOMContentLoaded', () => {
    console.log('micInit: DOMContentLoaded');

    // Get button element
    const grantMicBtn = document.getElementById('grant-mic');
    const micAllowedSpan = document.getElementById('mic-allowed');

    // Add click handler
    grantMicBtn.addEventListener('click', async () => {
      console.log('micInit: grantMicBtn.addEventListener.click');
      try {
        const stream = await micRequestAccess();
        micAllowedSpan.textContent = 'true';
      } catch (err) {
        micAllowedSpan.textContent = 'false';
      }
    });
  });

  console.log('micInit: end');
}

function micCheckAccess() {
  const constraints = {
    audio: true,
  };
}

async function micRequestAccess() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true, // Request microphone access
      video: false // Don't request camera access
    });

    // Access granted - stream contains the microphone audio track
    console.log('Microphone access granted');
    return stream;

  } catch (err) {
    // Handle errors:
    switch (err.name) {
      case 'NotAllowedError':
        console.error('User denied microphone access');
        break;
      case 'NotFoundError':
        console.error('No microphone found');
        break;
      case 'NotReadableError':
        console.error('Microphone is already in use');
        break;
      default:
        console.error('Error accessing microphone:', err);
    }
    throw err;
  }
}

function micRevokeAccess() {
  const constraints = {
    audio: false,
  };
}

function micGetPermission() {
  navigator.permissions.query({ name: 'microphone' });
}

function micStartRecording() {
  const constraints = {
    audio: true,
  };
}

function micStopRecording() {

}