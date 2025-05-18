<?php
require_once "config/db.php";
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Find My Career | Your Path to Success</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>

<body class="bg-gray-50 text-gray-800 font-sans">
  <!-- Hero Section -->
  <section
    class="bg-gradient-to-br from-orange-100 via-orange-200 to-orange-300 text-gray-800 py-32 px-6 text-center max-h-screen flex items-center justify-center">
    <div class="max-w-5xl mx-auto" x-data="{ visible: false }" x-init="visible = true" x-show="visible"
      x-transition:enter="transition ease-out duration-700"
      x-transition:enter-start="opacity-0 transform -translate-y-10"
      x-transition:enter-end="opacity-100 transform translate-y-0">
      <div class="flex flex-row items-center justify-center text-center gap-3">
        <div class="flex items-center justify-center">
          <img src="logo.png" class="w-16 h-16 md:w-24 md:h-24 mt-10" />
        </div>
        <h1 class="font-medium md:text-3xl text-xl leading-tight tracking-tight">
          Discover Your Career by <br>
          <span class="text-orange-600 md:text-9xl text-4xl">
            <span class="italic font-mono">Gyan</span>marg
          </span>
        </h1>
      </div>
      <p class="text-lg md:text-2xl mb-8 text-gray-600 max-w-3xl mx-auto">
        Explore IT jobs, master skills, and get AI-powered guidance to kickstart your journey after 12th grade.
      </p>
      <div class="space-x-4">
        <a href="login.php"
          class="bg-teal-600 text-white font-semibold px-8 py-4 rounded-lg shadow-lg hover:bg-teal-700 transform hover:scale-105 transition-all duration-300">
          Start for Free
        </a>
      </div>
    </div>
  </section>

  <!-- Features Section -->
  <section id="features" class="bg-white py-20 px-6">
    <div class="max-w-7xl mx-auto">
      <h2 class="text-4xl text-center mb-16 text-gray-800">Everything You Need to Succeed</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <!-- Job Exploration -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://images.unsplash.com/photo-1698047681432-006d2449c631?fm=jpg&q=60&w=3000&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8Mnx8am9iJTIwc2VhcmNofGVufDB8fDB8fHww');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">Explore Jobs Seamlessly</h3>
            <p class="text-gray-600 text-center mb-4">Find internships and entry-level IT jobs tailored for 12th
              pass/fail students, with filters for location, skills, and more.</p>
            <div class="text-center">
              <a href="explore.php"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">Explore
                Now</a>
            </div>
          </div>
        </div>

        <!-- Learning Center -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://plus.unsplash.com/premium_photo-1677531681337-4954c1970323?fm=jpg&q=60&w=3000&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MXx8c2tpbGxzfGVufDB8fDB8fHww');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">Skill Up with Ease</h3>
            <p class="text-gray-600 text-center mb-4">Learn HTML, JavaScript, and more through quizzes and tutorials
              designed for beginners.</p>
            <div class="text-center">
              <a href="learn.php"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">Start
                Learning</a>
            </div>
          </div>
        </div>

        <!-- AI Guidance -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://plus.unsplash.com/premium_photo-1683121710572-7723bd2e235d?fm=jpg&q=60&w=3000&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MXx8YXJ0aWZpY2lhbCUyMGludGVsbGlnZW5jZXxlbnwwfHwwfHx8MA%3D%3D');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">AI-Powered Guidance</h3>
            <p class="text-gray-600 text-center mb-4">Get personalized career advice and job recommendations with our AI
              assistant.</p>
            <div class="text-center">
              <a href="ai-assistant.php"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">Try
                AI Assistant</a>
            </div>
          </div>
        </div>

        <!-- Progress Tracking -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://images.unsplash.com/photo-1523966211575-eb4a01e7dd51?fit=crop&w=800&q=80');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">Track Your Progress</h3>
            <p class="text-gray-600 text-center mb-4">Monitor your learning and job application progress with insightful
              analytics.</p>
            <div class="text-center">
              <a href="dashboard.php"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">View
                Dashboard</a>
            </div>
          </div>
        </div>

        <!-- Community Support -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://images.unsplash.com/photo-1582213782179-e0d53f98f2ca?fm=jpg&q=60&w=3000&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8Mnx8Y29tbXVuaXR5JTIwZ3JvdXB8ZW58MHx8MHx8fDA%3D');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">Join Our Community</h3>
            <p class="text-gray-600 text-center mb-4">Connect with peers, share experiences, and get support in our
              student community forums.</p>
            <div class="text-center">
              <a href="#community"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">Join
                Now</a>
            </div>
          </div>
        </div>

        <!-- Resume Builder -->
        <div
          class="relative rounded-lg p-6 hover:shadow-lg transform hover:-translate-y-1 transition-all duration-300 bg-cover bg-center"
          style="background-image: url('https://images.unsplash.com/photo-1605379399642-870262d3d051?fit=crop&w=800&q=80');">
          <div class="absolute inset-0 bg-white/40 rounded-lg"></div>
          <div class="relative z-10">
            <h3 class="text-xl font-semibold mb-2 text-gray-800 text-center">Build Your Resume</h3>
            <p class="text-gray-600 text-center mb-4">Create a professional resume with our easy-to-use builder to stand
              out to employers.</p>
            <div class="text-center">
              <a href="#resume-builder"
                class="inline-block bg-teal-500 text-white px-4 py-2 rounded-lg hover:bg-teal-600 transform hover:scale-105 transition-all duration-200">Create
                Resume</a>
            </div>
          </div>
        </div>

      </div>
    </div>
  </section>


  <!-- Integrations Section -->
  <section class="bg-white text-black py-20 px-6">
    <div class="max-w-7xl mx-auto text-center">
      <h2 class="text-4xl  mb-6 text-black">Integrate with Your Our Tools</h2>
      <p class="text-lg mb-12 text-gray-800 max-w-2xl mx-auto">Enhance your career journey with seamless integrations to
        learning and productivity tools.</p>
      <div class="flex items-center justify-center lg:flex-row flex-col gap-8">
        <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSQB1yfZYXGl1BsF8o3MQfIhHQg8wiKEsvHxw&s"
          alt="Resume Builder"
          class="h-14 mx-auto  hover:opacity-100 transform hover:scale-110 transition-all duration-200 " />
        <img src="https://dslv9ilpbe7p1.cloudfront.net/hC86dioMgrKlB8WFPZYblQ_store_logo_image.png" alt="Up Skill"
          class="h-14 mx-auto opacity-80 hover:opacity-100 transform hover:scale-110 transition-all duration-200" />
      </div>
    </div>
  </section>

  <!-- Testimonial Section -->
  <section class="bg-white py-20 px-6">
    <div class="max-w-5xl mx-auto text-center">
      <h2 class="text-4xl mb-12 text-gray-800">What Our Users Say</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
        <blockquote class="bg-gray-200 rounded-xl p-6 transform hover:scale-105 transition-all duration-300">
          <p class="text-gray-600 italic text-lg mb-4">"Find My Career helped me land my first web development
            internship after 12th grade. The learning resources and job listings are a game-changer!"</p>
          <footer class="text-gray-800 font-semibold">— Priya Sharma, Aspiring Developer</footer>
        </blockquote>
        <blockquote class="bg-gray-200 rounded-xl p-6 transform hover:scale-105 transition-all duration-300">
          <p class="text-gray-600 italic text-lg mb-4">"The AI assistant gave me personalized tips that boosted my
            confidence to apply for IT jobs. Highly recommend!"</p>
          <footer class="text-gray-800 font-semibold">— Rohan Patel, IT Enthusiast</footer>
        </blockquote>
      </div>
    </div>
  </section>

  <!-- CTA Section -->
  <section class="bg-gray-900 text-white py-20 px-6 text-center">
    <div class="max-w-5xl mx-auto">
      <h2 class="text-4xl md:text-5xl mb-6">Ready to Shape Your Future?</h2>
      <p class="text-lg md:text-xl mb-8 text-gray-200 max-w-2xl mx-auto">Join thousands of students building their
        careers with Find My Career.</p>
      <div class="space-x-4 flex items-center justify-center">
        <a href="signup.php"
          class="bg-white text-black font-semibold px-8 py-4 rounded-lg shadow-lg hover:bg-gray-100 transform hover:scale-105 transition-all duration-300">
          Start for Free
        </a>
        <a href="#demo"
          class="bg-transparent border-2 border-white text-white px-8 py-4 rounded-lg hover:bg-white hover:text-black transform hover:scale-105 transition-all duration-300">
          Contact
        </a>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="bg-gray-900 text-white py-12 px-6">
    <div class="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8">
      <div>
        <h3 class="text-lg font-semibold mb-4">Find My Career</h3>
        <p class="text-gray-400 mb-2">hello@findmycareer.com</p>
        <p class="text-gray-400">+91 123-456-7890</p>
      </div>
      <div>
        <h3 class="text-lg font-semibold mb-4">Why Us</h3>
        <a href="#features" class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Our
          Features</a>
        <a href="#resources"
          class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Resources</a>
        <a href="#about" class="block text-gray-400 hover:text-teal-400 transition-colors duration-200">About Us</a>
      </div>
      <div>
        <h3 class="text-lg font-semibold mb-4">Product</h3>
        <a href="explore.php" class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Job
          Explorer</a>
        <a href="learn.php" class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Learning
          Center</a>
        <a href="ai-assistant.php" class="block text-gray-400 hover:text-teal-400 transition-colors duration-200">AI
          Assistant</a>
      </div>
      <div>
        <h3 class="text-lg font-semibold mb-4">Resources</h3>
        <a href="#blog" class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Blog</a>
        <a href="#privacy" class="block text-gray-400 hover:text-teal-400 mb-2 transition-colors duration-200">Privacy
          Policy</a>
        <a href="#terms" class="block text-gray-400 hover:text-teal-400 transition-colors duration-200">Terms of
          Service</a>
      </div>
    </div>
  </footer>

  <style>
    html {
      font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
    }

    ::-webkit-scrollbar {
      display: none;
    }

    body {
      -ms-overflow-style: none;
      scrollbar-width: none;
    }
  </style>
</body>

</html>
