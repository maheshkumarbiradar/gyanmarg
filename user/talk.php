<?php
require_once "../config/db.php";
protect();
$username = $_SESSION['username'] ?? '';
?>

<!DOCTYPE html>
<html lang="en">
<?php get_head("talk - Find My Career"); ?>

<body class="min-h-screen flex flex-col bg-white text-gray-800">

  <div class="flex flex-col md:flex-row w-full">
    <!-- Sidebar -->
    <?php include("./includes/sidebar.php"); ?>

    <!-- Main Content -->
    <main class="flex-1 p-4 md:p-6 w-full overflow-y-auto">
      <!-- Welcome Section -->
      <section class="mb-6 ">
        <h2 class="text-3xl text-gray-800">Talk to AI</h2>
        <p class="text-gray-600 text-sm mt-1">Clear all your questions with our AI</p>
      </section>
      <div class="w-full h-screen p-2">
      <canvas id="bg-canvas"></canvas>
<div id="root" role="main" aria-label="Career guidance voice assistant">
  <header>
    <h1>Voice Career Assistant</h1>
    <select id="language-select" aria-label="Select language to communicate">
      <option value="en-IN">English (India)</option>
      <option value="hi-IN">Hindi</option>
    </select>
  </header>

  <div id="chat-box" aria-live="polite" aria-atomic="false" role="log"></div>

  <button id="control-button" aria-label="Start voice interaction">Start Conversation</button>
</div>
      </div>
    </main>
  </div>

  <?php include("includes/bottom.php"); ?>
  <script src="https://cdn.jsdelivr.net/npm/three@0.154.0/build/three.min.js"></script>
<script>
  // 3D background - a simple rotating glowing sphere
  (() => {
    const canvas = document.getElementById('bg-canvas');
    const renderer = new THREE.WebGLRenderer({canvas: canvas, antialias: true, alpha:true});
    renderer.setSize(window.innerWidth, window.innerHeight);
    const scene = new THREE.Scene();

    const camera = new THREE.PerspectiveCamera(45, window.innerWidth/window.innerHeight, 0.1, 1000);
    camera.position.z = 6;

    // Glow sphere
    const geometry = new THREE.SphereGeometry(1.7, 64, 64);
    const material = new THREE.MeshStandardMaterial({
      color: 0xf0a500, transparent: true, opacity: 0.5,
      roughness: 0.2, metalness: 0.9,
      emissive: 0xf0a500, emissiveIntensity: 0.7
    });
    const sphere = new THREE.Mesh(geometry, material);
    scene.add(sphere);

    // Light
    const pointLight = new THREE.PointLight(0xf0a500, 1.5, 100);
    pointLight.position.set(5, 5, 5);
    scene.add(pointLight);
    const ambientLight = new THREE.AmbientLight(0x404040, 0.7);
    scene.add(ambientLight);

    // Animation loop
    function animate() {
      requestAnimationFrame(animate);
      sphere.rotation.y += 0.005;
      sphere.rotation.x += 0.003;
      renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', () => {
      camera.aspect = window.innerWidth/window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    });
  })();

  // Voice Assistant Logic
  (() => {
    const chatBox = document.getElementById('chat-box');
    const startButton = document.getElementById('control-button');
    const languageSelect = document.getElementById('language-select');

    // Questions list for profiling
    const questions = [
      {
        id: 1,
        en: "Hello! To start, please tell me your education level. For example, high school, ITI, or PUC.",
        hi: "नमस्ते! शुरू करने के लिए, कृपया मुझे अपनी शिक्षा स्तर बताएं। जैसे हाई स्कूल, ITI, या PUC।"
      },
      {
        id: 2,
        en: "Great! What is your preferred language to learn and communicate?",
        hi: "बहुत अच्छे! सीखने और बातचीत के लिए आपकी पसंदीदा भाषा क्या है?"
      },
      {
        id: 3,
        en: "Could you tell me about your interests? For example, creative, technical, or service-oriented?",
        hi: "क्या आप मुझे अपने रुचियों के बारे में बता सकते हैं? जैसे, रचनात्मक, तकनीकी या सेवा-उन्मुख?"
      },
      {
        id: 4,
        en: "Do you belong to an underserved segment like women, school dropout, or aspirant from an agricultural family?",
        hi: "क्या आप किसी वंचित वर्ग से संबंधित हैं जैसे महिलाएं, स्कूल ड्रॉपआउट, या कृषि परिवार से उम्मीदवार?"
      },
      {
        id: 5,
        en: "Thanks for sharing! I will now find the best career opportunities for you.",
        hi: "साझा करने के लिए धन्यवाद! मैं अब आपके लिए सबसे अच्छे कैरियर के अवसर खोजूंगा।"
      }
    ];

    // Global state
    let currentQuestionIndex = 0;
    let userResponses = {};
    let recognizing = false;

    // Speech Recognition setup
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      alert("Sorry, your browser does not support Speech Recognition API. Please use Chrome or Edge.");
    }
    const recognition = SpeechRecognition ? new SpeechRecognition() : null;
    recognition.interimResults = false;
    recognition.continuous = false;

    // Text-to-speech
    function speak(text, lang) {
      return new Promise((resolve) => {
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = lang;
        utterance.rate = 1;
        utterance.pitch = 1.1;
        utterance.onend = () => resolve();
        window.speechSynthesis.speak(utterance);
      });
    }

    // Show message in chat box
    function showMessage(text, sender = 'assistant') {
      const messageDiv = document.createElement('div');
      messageDiv.classList.add('message', sender);
      messageDiv.textContent = text;
      chatBox.appendChild(messageDiv);
      chatBox.scrollTop = chatBox.scrollHeight;
    }

    // Assistant asks question then listens for user's answer
    async function askThenListen() {
      if (currentQuestionIndex >= questions.length) {
        showMessage("Conversation completed. Thank you!", 'assistant');
        startButton.textContent = "Restart Conversation";
        startButton.disabled = false;
        return;
      }

      const langCode = languageSelect.value;
      const questionObj = questions[currentQuestionIndex];
      const questionText = questionObj[langCode.startsWith('hi') ? 'hi' : 'en'];

      // Assistant asks
      showMessage(questionText, 'assistant');
      await speak(questionText, langCode);

      // Listen for answer
      startButton.textContent = "Listening...";
      startButton.disabled = true;
      recognizing = true;

      recognition.lang = langCode;
      recognition.start();

      recognition.onresult = (event) => {
        recognizing = false;
        const transcript = event.results[0][0].transcript;
        showMessage(transcript, 'user');
        userResponses[questionObj.id] = transcript;
        currentQuestionIndex++;
        startButton.textContent = "Continue Conversation";
        startButton.disabled = false;
      };
      recognition.onerror = (event) => {
        recognizing = false;
        showMessage("I didn't catch that. Please try again.", 'assistant');
        speak(languageSelect.value.startsWith('hi') ? "माफ़ करें, मैं समझ नहीं पाया। कृपया फिर से कोशिश करें।" : "I didn't catch that. Please try again.", languageSelect.value);
        startButton.textContent = "Try Again";
        startButton.disabled = false;
      };

      recognition.onend = () => {
        if (recognizing) {
          // sometimes onend fires before onresult
          recognition.start();
        }
      };
    }

    startButton.addEventListener('click', () => {
      if (currentQuestionIndex === questions.length) {
        // Restart conversation
        currentQuestionIndex = 0;
        userResponses = {};
        chatBox.innerHTML = "";
        startButton.textContent = "Start Conversation";
        return;
      }
      askThenListen();
    });

    // Accessibility: keyboard enter triggers button
    startButton.addEventListener('keyup', (e) => {
      if (e.key === 'Enter' || e.key === ' ') startButton.click();
    });
  })();
</script>
</body>

<style>
  html {
    font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
  }
</style>

</html>
