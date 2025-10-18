/**
 * ===================================================================
 * MONOLITHIC Node.js Server for the EHR Blockchain System
 * ===================================================================
 * This single file contains:
 * 1. The Express.js server setup.
 * 2. The backend API endpoints for authentication and record management.
 * 3. The connection to the Ganache blockchain via Web3.js.
 * 4. Routes that serve the complete HTML, CSS, and client-side JavaScript
 * for every page of the application.
 *
 * To Run: `node server.js`
 * ===================================================================
 */

// -----------------------------------------------------------
// PART 1: CORE SERVER SETUP AND API LOGIC
// -----------------------------------------------------------
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Web3 = require('web3').default;
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Middleware Setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Serve static assets like images from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


// -----------------------------------------------------------
// BLOCKCHAIN AND WEB3 SETUP
// -----------------------------------------------------------
const GANACHE_URL = 'http://127.0.0.1:7545';
const web3 = new Web3(GANACHE_URL);

// !!! IMPORTANT: Update these based on your deployed EHRRegistry contract !!!
const CONTRACT_ADDRESS = '0x19520281DbDfC4Ced8bBc2137e216A2253a6ea71';
const HOSPITAL_ADMIN_WALLET = '0x438F79734E505bbED16dD23D8097DB1a96a22B2a';
const HOSPITAL_ADMIN_PRIVATE_KEY = '0xf70f9c4e969398ab9d71a2050f16e368870130282a40cbd00a776ff462470c17';

let ehrContract;

try {
    const abiPath = path.join(__dirname, 'build/contracts/EHRRegistry.json');
    const EHRRegistryABI = require(abiPath).abi;
    ehrContract = new web3.eth.Contract(EHRRegistryABI, CONTRACT_ADDRESS);
    console.log('[Web3] EHRRegistry Contract loaded successfully.');
} catch (e) {
    console.error('[Web3] ERROR: Could not load contract ABI. Ensure "build/contracts/EHRRegistry.json" exists and you have run "truffle migrate".', e);
}


// -----------------------------------------------------------
// SIMULATED DATABASE SETUP
// -----------------------------------------------------------
const EHR_DB_PATH = path.join(__dirname, 'ehr_db.json');
let ehrDB = {};

function loadDB() {
    try {
        if (fs.existsSync(EHR_DB_PATH)) {
            const data = fs.readFileSync(EHR_DB_PATH, 'utf8');
            ehrDB = data ? JSON.parse(data) : {};
            console.log(`[DB] Loaded ${Object.keys(ehrDB).length} user records.`);
        } else {
            fs.writeFileSync(EHR_DB_PATH, JSON.stringify({}), 'utf8');
            console.log(`[DB] Created empty EHR database file.`);
        }
    } catch (e) {
        console.error('[DB] CRITICAL ERROR loading EHR database:', e);
        ehrDB = {};
    }
}

function saveDB() {
    try {
        fs.writeFileSync(EHR_DB_PATH, JSON.stringify(ehrDB, null, 4), 'utf8');
        console.log(`[DB] Successfully saved ${Object.keys(ehrDB).length} user records.`);
    } catch (e) {
        console.error('[DB] CRITICAL ERROR saving EHR database:', e);
    }
}

loadDB();

// -----------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------
function hashData(data) {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
}


// -----------------------------------------------------------
// BACKEND API ENDPOINTS
// -----------------------------------------------------------

// --- AUTHENTICATION API ---
app.post('/api/auth/register', async (req, res) => {
    const { name, mailId, password, role, ...otherDetails } = req.body;
    if (!mailId || !password || !name || !role) { return res.status(400).json({ success: false, message: 'Missing required fields.' }); }
    if (ehrDB[mailId]) { return res.status(409).json({ success: false, message: `User with email ${mailId} already exists.` }); }
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        ehrDB[mailId] = { name, mailId, hashedPassword, role, ...otherDetails, ethAddress: null, records: role === 'Patient' ? [] : undefined };
        saveDB();
        res.json({ success: true, message: `Account for ${mailId} created successfully. Please complete on-chain registration.` });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error during registration.' }); }
});

app.post('/api/auth/save-eth-address', (req, res) => {
    const { mailId, ethAddress } = req.body;
    if (!mailId || !ethAddress) { return res.status(400).json({ success: false, message: 'Email and ETH address are required.' }); }
    if (!ehrDB[mailId]) { return res.status(404).json({ success: false, message: 'User not found.' }); }
    ehrDB[mailId].ethAddress = ethAddress;
    saveDB();
    res.json({ success: true, message: 'Ethereum address linked successfully.' });
});

app.post('/api/auth/login', async (req, res) => {
    const { mailId, password } = req.body;
    if (!mailId || !password) { return res.status(400).json({ success: false, message: 'Email and Password are required.' }); }
    const userRecord = ehrDB[mailId];
    if (!userRecord) { return res.status(404).json({ success: false, message: 'Invalid Email or account not found.' }); }
    try {
        const isMatch = await bcrypt.compare(password, userRecord.hashedPassword);
        if (isMatch) {
            res.json({ success: true, message: 'Login successful.', user: { name: userRecord.name, mailId: userRecord.mailId, role: userRecord.role, ethAddress: userRecord.ethAddress } });
        } else {
            res.status(401).json({ success: false, message: 'Invalid password.' });
        }
    } catch (error) { res.status(500).json({ success: false, message: 'Internal server error.' }); }
});

// --- RECORD MANAGEMENT API ---
app.post('/api/records/add', async (req, res) => {
    const { patientMailId, ...recordData } = req.body;
    const patient = ehrDB[patientMailId];
    if (!patient || patient.role !== 'Patient' || !patient.ethAddress) { return res.status(404).json({ success: false, message: `Patient not found or not registered on-chain.` }); }
    try {
        const recordHash = '0x' + hashData(recordData);
        if (!ehrContract) { throw new Error("Blockchain contract not initialized."); }
        const txData = ehrContract.methods.addRecord(recordHash, patient.ethAddress).encodeABI();
        const gasEstimate = await web3.eth.estimateGas({ from: HOSPITAL_ADMIN_WALLET, to: CONTRACT_ADDRESS, data: txData });
        const gasPrice = await web3.eth.getGasPrice();
        const tx = { from: HOSPITAL_ADMIN_WALLET, to: CONTRACT_ADDRESS, data: txData, gas: gasEstimate.toString(), gasPrice: gasPrice.toString() };
        const signedTx = await web3.eth.accounts.signTransaction(tx, HOSPITAL_ADMIN_PRIVATE_KEY);
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        patient.records.push({ recordHash, recordData, issuer: HOSPITAL_ADMIN_WALLET, blockchainTxHash: receipt.transactionHash, issueTimestamp: new Date().toISOString() });
        saveDB();
        res.json({ success: true, message: 'Medical record added and confirmed on blockchain.', hash: recordHash, txHash: receipt.transactionHash });
    } catch (error) { res.status(500).json({ success: false, message: `Failed to add record: ${error.message}` }); }
});

app.get('/api/patient/records/:mailId', (req, res) => {
    const { mailId } = req.params;
    const patient = ehrDB[mailId];
    if (!patient || patient.role !== 'Patient') { return res.status(404).json({ success: false, message: 'Patient not found.' }); }
    res.json({ success: true, records: patient.records || [] });
});

app.get('/api/users/eth-address/:mailId', (req, res) => {
    const { mailId } = req.params;
    const user = ehrDB[mailId];
    if (!user || (user.role !== 'Doctor' && user.role !== 'Admin') || !user.ethAddress) { return res.status(404).json({ success: false, message: 'Professional not found or not registered on-chain.' }); }
    res.json({ success: true, ethAddress: user.ethAddress });
});

app.get('/api/professional/view-patient-records/:patientEmail', async (req, res) => {
    // A real app would get the professional's ETH address from a secure session/token.
    // For this example, we'll assume the main admin/doctor is viewing.
    const professionalEthAddress = HOSPITAL_ADMIN_WALLET; 
    const patient = ehrDB[req.params.patientEmail];
    if (!patient || patient.role !== 'Patient') { return res.status(404).json({ success: false, message: 'Patient not found.' }); }
    try {
        if (!ehrContract) { throw new Error("Blockchain contract not initialized."); }
        const accessibleRecords = [];
        for (const record of patient.records) {
            const hasAccess = await ehrContract.methods.checkAccess(record.recordHash, professionalEthAddress).call();
            if (hasAccess) {
                accessibleRecords.push(record);
            }
        }
        res.json({ success: true, records: accessibleRecords });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error verifying access: ${error.message}` });
    }
});


// -----------------------------------------------------------
// PART 2: PAGE SERVING ROUTES (Serving HTML, CSS, JS)
// -----------------------------------------------------------

// --- Homepage (index.html) with Registration Links ---
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>EHR Chain - Secure Health Record System</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/lucide@latest"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
            html { scroll-behavior: smooth; }
            body { font-family: 'Inter', sans-serif; background-color: #0d9488; background-image: linear-gradient(to right bottom, #06b6d4, #22c55e); }
            .cta-button { background-image: linear-gradient(to right, #ec4899, #f97316); }
        </style>
    </head>
    <body class="text-white">
        <header class="absolute top-0 left-0 right-0 p-6 z-10"><div class="container mx-auto flex justify-between items-center"><div class="flex items-center gap-3"><i data-lucide="link" class="w-8 h-8 text-white"></i><span class="text-xl font-bold">EHR Chain</span></div></div></header>
        <section class="min-h-screen flex items-center justify-center text-center px-4"><div class="max-w-4xl"><h1 class="text-5xl md:text-7xl font-extrabold leading-tight">Securely Manage & Share Health Records on the Blockchain</h1><p class="mt-6 text-lg md:text-xl text-white/80 max-w-2xl mx-auto">EHR Chain provides a secure, transparent, and patient-centric platform for managing and sharing electronic health records using the power of blockchain technology.</p><a href="#portals" class="cta-button inline-block mt-10 px-8 py-4 text-lg font-bold text-white rounded-full shadow-lg hover:scale-105 transition-transform duration-300">Get Started &rarr;</a></div></section>
        
        <section id="portals" class="py-20 sm:py-32 px-4">
            <div class="container mx-auto text-center">
                <h2 class="text-4xl font-bold mb-12">Access Your Portal</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                    
                    <div class="p-8 rounded-2xl h-full flex flex-col items-center text-center bg-gradient-to-br from-pink-500 to-orange-400 shadow-xl">
                        <img src="/imgs/admin.png" alt="Admin Icon" class="w-16 h-16 mb-4">
                        <h3 class="text-2xl font-bold mb-2 text-white">Hospital Admin</h3>
                        <p class="text-white/80 mb-6 flex-grow">Manage hospital-wide settings and add medical records for patients.</p>
                        <div class="mt-auto">
                           <a href="/admin/login" class="font-bold text-white inline-block px-6 py-3 rounded-full bg-white/20 hover:bg-white/30 transition-colors">Admin Login &rarr;</a>
                        </div>
                    </div>

                    <div class="p-8 rounded-2xl h-full flex flex-col items-center text-center bg-gradient-to-br from-pink-500 to-orange-400 shadow-xl">
                        <img src="/imgs/verifier.png" alt="Doctor Icon" class="w-16 h-16 mb-4">
                        <h3 class="text-2xl font-bold mb-2 text-white">Doctor Portal</h3>
                        <p class="text-white/80 mb-6 flex-grow">Log in to add new medical records and view records shared by your patients.</p>
                        <div class="mt-auto text-center">
                           <a href="/doctor/login" class="font-bold text-white inline-block px-6 py-3 rounded-full bg-white/20 hover:bg-white/30 transition-colors">Doctor Login &rarr;</a>
                           <p class="mt-3 text-sm">New User? <a href="/doctor/register" class="font-bold hover:underline">Register Here</a></p>
                        </div>
                    </div>

                    <div class="p-8 rounded-2xl h-full flex flex-col items-center text-center bg-gradient-to-br from-pink-500 to-orange-400 shadow-xl">
                        <img src="/imgs/student.png" alt="Patient Icon" class="w-16 h-16 mb-4">
                        <h3 class="text-2xl font-bold mb-2 text-white">Patient Portal</h3>
                        <p class="text-white/80 mb-6 flex-grow">View your health records, and grant or revoke access for healthcare providers.</p>
                        <div class="mt-auto text-center">
                           <a href="/patient/login" class="font-bold text-white inline-block px-6 py-3 rounded-full bg-white/20 hover:bg-white/30 transition-colors">Patient Login &rarr;</a>
                           <p class="mt-3 text-sm">New User? <a href="/patient/register" class="font-bold hover:underline">Register Here</a></p>
                        </div>
                    </div>

                </div>
            </div>
        </section>
        
        <footer class="py-12 text-center text-white/60"><div class="container mx-auto">© ${new Date().getFullYear()} EHR Chain | A Secure Health Records Platform</div></footer>
        <script>window.onload = () => { if (typeof lucide !== 'undefined') { lucide.createIcons(); } };</script>
    </body>
    </html>
    `);
});


// --- Generic Login Page Function ---
function getLoginPageHTML(role) {
    const roleTitle = role.charAt(0).toUpperCase() + role.slice(1);
    const registerLink = role === 'admin' ? '' : `<p class="text-center mt-4 text-sm">Don't have an account? <a href="/${role}/register" class="font-bold hover:underline">Register here</a></p>`;

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${roleTitle} Login - EHR Chain</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap'); body { font-family: 'Inter', sans-serif; background-image: linear-gradient(to right bottom, #06b6d4, #22c55e); }</style>
    </head>
    <body class="min-h-screen flex items-center justify-center">
        <div class="bg-white/10 backdrop-blur-lg p-8 rounded-2xl shadow-xl w-full max-w-md text-white border border-white/20">
            <h2 class="text-3xl font-bold text-center mb-6">${roleTitle} Login</h2>
            <form id="loginForm">
                <div class="mb-4"><label for="mailId" class="block mb-2 text-sm font-medium">Email Address</label><input type="email" id="mailId" name="mailId" required class="w-full bg-white/20 border border-white/30 rounded-lg px-4 py-2 focus:ring-2 focus:ring-pink-500 focus:outline-none placeholder-white/60"></div>
                <div class="mb-6"><label for="password" class="block mb-2 text-sm font-medium">Password</label><input type="password" id="password" name="password" required class="w-full bg-white/20 border border-white/30 rounded-lg px-4 py-2 focus:ring-2 focus:ring-pink-500 focus:outline-none"></div>
                <button type="submit" class="w-full bg-gradient-to-r from-pink-500 to-orange-500 text-white font-bold py-3 px-4 rounded-lg hover:scale-105 transition-transform duration-300">Login</button>
            </form>
            ${registerLink}
            <div id="message" class="mt-4 text-center"></div>
        </div>
        <script>
            document.addEventListener('DOMContentLoaded', () => {
                const loginForm = document.getElementById('loginForm');
                const messageDiv = document.getElementById('message');
                const redirectUrl = '/${role}/dashboard';
                const expectedRole = '${roleTitle}';

                loginForm.addEventListener('submit', async function (e) {
                    e.preventDefault();
                    const mailId = document.getElementById('mailId').value;
                    const password = document.getElementById('password').value;
                    messageDiv.textContent = 'Logging in...';
                    try {
                        const response = await fetch('/api/auth/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ mailId, password }),
                        });
                        const result = await response.json();
                        if (result.success && result.user.role === expectedRole) {
                            localStorage.setItem('ehrUser', JSON.stringify(result.user));
                            window.location.href = redirectUrl;
                        } else {
                            throw new Error(result.message || 'Access denied for this role.');
                        }
                    } catch (error) {
                        messageDiv.textContent = error.message;
                        messageDiv.style.color = '#f87171';
                    }
                });
            });
        </script>
    </body>
    </html>`;
}

app.get('/admin/login', (req, res) => res.send(getLoginPageHTML('admin')));
app.get('/doctor/login', (req, res) => res.send(getLoginPageHTML('doctor')));
app.get('/patient/login', (req, res) => res.send(getLoginPageHTML('patient')));


// --- Registration Pages ---
app.get('/:role(admin|doctor|patient)/register', (req, res) => {
    const role = req.params.role;
    const roleTitle = role.charAt(0).toUpperCase() + role.slice(1);
    
    let fields = '';
    if (role === 'patient') {
        fields = `<div class="md:col-span-2"><label class="block mb-1 text-sm">Full Name</label><input type="text" name="name" required class="input-field"></div><div class="md:col-span-2"><label class="block mb-1 text-sm">Email</label><input type="email" name="mailId" required class="input-field"></div><div><label class="block mb-1 text-sm">Password</label><input type="password" name="password" required class="input-field"></div><div><label class="block mb-1 text-sm">Mobile</label><input type="tel" name="mobile" required class="input-field"></div>`;
    } else if (role === 'doctor') {
        fields = `<div class="md:col-span-2"><label class="block mb-1 text-sm">Full Name</label><input type="text" name="name" required class="input-field"></div><div class="md:col-span-2"><label class="block mb-1 text-sm">Email</label><input type="email" name="mailId" required class="input-field"></div><div><label class="block mb-1 text-sm">Password</label><input type="password" name="password" required class="input-field"></div><div><label class="block mb-1 text-sm">Qualification</label><input type="text" name="qualification" required class="input-field"></div>`;
    } else { // Admin
        fields = `<div class="md:col-span-2"><label class="block mb-1 text-sm">Full Name</label><input type="text" name="name" required class="input-field"></div><div class="md:col-span-2"><label class="block mb-1 text-sm">Email</label><input type="email" name="mailId" required class="input-field"></div><div><label class="block mb-1 text-sm">Password</label><input type="password" name="password" required class="input-field"></div><div><label class="block mb-1 text-sm">Hospital</label><input type="text" name="hospitalName" required class="input-field"></div>`;
    }
    
    res.send(`
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>${roleTitle} Registration</title><script src="https://cdn.tailwindcss.com"></script><script src="/js/ethers.umd.min.js"></script></script><style>body{font-family:Inter,sans-serif;background-image:linear-gradient(to right bottom,#06b6d4,#22c55e)}.input-field{background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.3);border-radius:.5rem;padding:.5rem 1rem;width:100%;color:white;}</style></head>
    <body class="min-h-screen flex items-center justify-center py-12"><div class="bg-white/10 backdrop-blur-lg p-8 rounded-2xl shadow-xl w-full max-w-lg text-white"><div id="accountStep"><h2 class="text-3xl font-bold text-center mb-1">${roleTitle} Registration</h2><p class="text-center text-white/70 mb-6">Step 1: Create Account</p><form id="registerForm"><input type="hidden" name="role" value="${roleTitle}"><div class="grid grid-cols-1 md:grid-cols-2 gap-4">${fields}</div><button type="submit" class="w-full mt-6 bg-gradient-to-r from-pink-500 to-orange-500 text-white font-bold py-3 rounded-lg">Create Account</button></form><p class="text-center mt-4 text-sm">Already have an account? <a href="/${role}/login" class="font-bold">Login</a></p></div><div id="blockchainStep" class="hidden mt-6 pt-6 border-t border-white/20"><h3 class="text-2xl font-bold text-center">Step 2: Register on Blockchain</h3><p class="text-center my-4">Connect wallet to create your on-chain identity.</p><button id="registerOnChain" class="w-full bg-blue-600 text-white font-bold py-3 rounded-lg">Connect & Register</button></div><div id="message" class="mt-4 text-center font-medium"></div></div>
    <script>
        const roleEnumMap = { 'patient': 0, 'doctor': 1, 'admin': 2 };
        // --- IMPORTANT: PASTE YOUR CONTRACT DETAILS HERE ---
        const contractAddress = '${CONTRACT_ADDRESS}';
        const contractABI = ${JSON.stringify(ehrContract ? ehrContract.options.jsonInterface.map(i => ({...i})) : [])};
        // ----------------------------------------------------
        document.addEventListener('DOMContentLoaded', () => {
            const registerForm = document.getElementById('registerForm');
            const messageDiv = document.getElementById('message');
            const accountStepDiv = document.getElementById('accountStep');
            const blockchainStepDiv = document.getElementById('blockchainStep');
            const registerOnChainBtn = document.getElementById('registerOnChain');
            let userEmailForChain = '';
            registerForm.addEventListener('submit', async e => {
                e.preventDefault();
                const data = Object.fromEntries(new FormData(registerForm).entries());
                userEmailForChain = data.mailId;
                messageDiv.textContent = 'Creating account...';
                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
                    const result = await res.json();
                    if (!res.ok) throw new Error(result.message);
                    accountStepDiv.classList.add('hidden');
                    blockchainStepDiv.classList.remove('hidden');
                    messageDiv.textContent = 'Account created. Please complete blockchain registration.';
                } catch (err) { messageDiv.textContent = err.message; }
            });
            registerOnChainBtn.addEventListener('click', async () => {
                if(!window.ethereum) { messageDiv.textContent = 'MetaMask is not installed.'; return; }
                try {
                    messageDiv.textContent = 'Please approve transaction in MetaMask...';
                    const provider = new ethers.providers.Web3Provider(window.ethereum);
                    await provider.send("eth_requestAccounts", []);
                    const signer = provider.getSigner();
                    const userAddress = await signer.getAddress();
                    const contract = new ethers.Contract(contractAddress, contractABI, signer);
                    const tx = await contract.registerUser(userEmailForChain, roleEnumMap['${role}']);
                    await tx.wait();
                    await fetch('/api/auth/save-eth-address', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mailId: userEmailForChain, ethAddress: userAddress }) });
                    blockchainStepDiv.innerHTML = '<h3 class="text-2xl text-center text-green-400">Registration Complete!</h3><a href="/${role}/login" class="block text-center mt-4 font-bold bg-green-600 p-3 rounded-lg">Proceed to Login</a>';
                } catch (err) { messageDiv.textContent = 'Error: ' + (err.reason || err.message); }
            });
        });
    </script></body></html>`);
});


// --- Dashboard Pages ---
app.get('/:role(admin|doctor)/dashboard', (req, res) => {
    const role = req.params.role;
    const roleTitle = role.charAt(0).toUpperCase() + role.slice(1);
    res.send(`
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>${roleTitle} Dashboard</title><script src="https://cdn.tailwindcss.com"></script><style>body{font-family:Inter,sans-serif;background-image:linear-gradient(to right bottom,#06b6d4,#22c55e)}.card{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:white}.input-field{background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.3);border-radius:.5rem;padding:.5rem 1rem;color:white}</style></head>
    <body class="text-white min-h-screen"><header class="bg-black/20 p-4"><div class="container mx-auto flex justify-between items-center"><h1 class="text-xl font-bold">${roleTitle} Dashboard</h1><div><span id="userName" class="mr-4"></span><button id="logoutBtn" class="bg-red-500 px-4 py-2 rounded-lg text-sm font-bold">Logout</button></div></div></header>
    <main class="container mx-auto p-8"><div class="grid grid-cols-1 lg:grid-cols-2 gap-8"><div class="card p-6 rounded-2xl"><h2 class="text-2xl font-bold mb-4">Add New Medical Record</h2><form id="addRecordForm"><div class="mb-4"><label for="patientMailId" class="block mb-2 text-sm">Patient Email</label><input type="email" id="patientMailId" required class="w-full input-field"></div><div class="grid grid-cols-2 gap-4 mb-4"><input type="text" name="bloodGroup" placeholder="Blood Group" class="input-field"><input type="number" step="0.1" name="bmi" placeholder="BMI" class="input-field"></div><textarea name="healthCondition" rows="3" placeholder="Notes..." class="w-full input-field"></textarea><button type="submit" class="w-full mt-4 bg-gradient-to-r from-pink-500 to-orange-500 font-bold py-3 rounded-lg">Add Record</button></form><div id="addRecordMessage" class="mt-4 text-center"></div></div>
    <div class="card p-6 rounded-2xl"><h2 class="text-2xl font-bold mb-4">View Patient Records</h2><form id="viewRecordsForm" class="flex gap-2"><input type="email" id="viewPatientMailId" placeholder="Patient Email" required class="flex-grow input-field"><button type="submit" class="bg-blue-600 font-bold py-2 px-6 rounded-lg">Fetch</button></form><div id="recordsContainer" class="mt-4 space-y-4 max-h-[24rem] overflow-y-auto"></div><div id="viewRecordsMessage" class="mt-4 text-center"></div></div></div></main>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const user = JSON.parse(localStorage.getItem('ehrUser'));
            if (!user || user.role !== '${roleTitle}') { window.location.href = '/${role}/login'; return; }
            document.getElementById('userName').textContent = 'Welcome, ' + user.name;
            document.getElementById('logoutBtn').addEventListener('click', () => { localStorage.removeItem('ehrUser'); window.location.href = '/'; });
            document.getElementById('addRecordForm').addEventListener('submit', async e => {
                e.preventDefault();
                const msgDiv = document.getElementById('addRecordMessage');
                const data = Object.fromEntries(new FormData(e.target).entries());
                data.patientMailId = document.getElementById('patientMailId').value;
                msgDiv.textContent = 'Submitting record...';
                try {
                    const res = await fetch('/api/records/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
                    const result = await res.json();
                    if (!res.ok) throw new Error(result.message);
                    msgDiv.textContent = 'Record added successfully!';
                    e.target.reset();
                } catch (err) { msgDiv.textContent = 'Error: ' + err.message; }
            });
            document.getElementById('viewRecordsForm').addEventListener('submit', async e => {
                e.preventDefault();
                const msgDiv = document.getElementById('viewRecordsMessage');
                const container = document.getElementById('recordsContainer');
                const patientEmail = document.getElementById('viewPatientMailId').value;
                container.innerHTML = ''; msgDiv.textContent = 'Fetching records...';
                try {
                    const res = await fetch('/api/professional/view-patient-records/' + patientEmail);
                    const result = await res.json();
                    if (!res.ok) throw new Error(result.message);
                    if (result.records.length === 0) { msgDiv.textContent = 'No accessible records found.'; } else { msgDiv.textContent = ''; }
                    result.records.forEach(r => {
                        const el = document.createElement('div'); el.className = 'bg-black/20 p-4 rounded-lg text-sm';
                        el.innerHTML = '<strong>Record:</strong> ' + (r.recordData.healthCondition || 'N/A');
                        container.appendChild(el);
                    });
                } catch (err) { msgDiv.textContent = 'Error: ' + err.message; }
            });
        });
    </script></body></html>`);
});

app.get('/patient/dashboard', (req, res) => {
    res.send(`
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Patient Dashboard</title><script src="https://cdn.tailwindcss.com"></script><script src="<script src="/js/ethers.umd.min.js"></script>"></script><style>body{font-family:Inter,sans-serif;background-image:linear-gradient(to right bottom,#06b6d4,#22c55e)}.card{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:white}</style></head>
    <body class="text-white min-h-screen"><header class="bg-black/20 p-4"><div class="container mx-auto flex justify-between items-center"><h1 class="text-xl font-bold">Patient Dashboard</h1><div><span id="userName" class="mr-4"></span><button id="logoutBtn" class="bg-red-500 px-4 py-2 rounded-lg text-sm">Logout</button></div></div></header>
    <main class="container mx-auto p-8"><h2 class="text-3xl font-bold mb-6">Your Medical Records</h2><div id="recordsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div><div id="message" class="text-center mt-8"></div></main>
    <div id="shareModal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center p-4"><div class="card rounded-2xl p-8 w-full max-w-md"><h3 class="text-2xl font-bold mb-4">Share Medical Record</h3><form id="shareForm"><input type="hidden" id="recordHashToShare"><div class="mb-4"><label for="shareWithEmail">Doctor/Admin Email</label><input type="email" id="shareWithEmail" required class="w-full bg-white/20 border-white/30 rounded-lg p-2 mt-2"></div><div class="flex gap-4 mt-6"><button type="button" id="cancelShare" class="w-full bg-white/20 py-2 rounded-lg">Cancel</button><button type="submit" class="w-full bg-gradient-to-r from-pink-500 to-orange-500 font-bold py-2 rounded-lg">Grant Access</button></div></form><div id="shareMessage" class="mt-4 text-center"></div></div></div>
    <script>
        // --- IMPORTANT: PASTE YOUR CONTRACT DETAILS HERE ---
        const contractAddress = '${CONTRACT_ADDRESS}';
        const contractABI = ${JSON.stringify(ehrContract ? ehrContract.options.jsonInterface.map(i => ({...i})) : [])};
        // ----------------------------------------------------
        document.addEventListener('DOMContentLoaded', () => {
            const user = JSON.parse(localStorage.getItem('ehrUser'));
            if (!user || user.role !== 'Patient') { window.location.href = '/patient/login'; return; }
            document.getElementById('userName').textContent = 'Welcome, ' + user.name;
            document.getElementById('logoutBtn').addEventListener('click', () => { localStorage.removeItem('ehrUser'); window.location.href = '/'; });
            const recordsGrid = document.getElementById('recordsGrid');
            const messageDiv = document.getElementById('message');
            const shareModal = document.getElementById('shareModal');
            const shareForm = document.getElementById('shareForm');
            async function loadRecords() {
                messageDiv.textContent = 'Loading records...';
                const res = await fetch('/api/patient/records/' + user.mailId);
                const result = await res.json();
                if(!result.success || result.records.length === 0) { messageDiv.textContent = 'No records found.'; recordsGrid.innerHTML = ''; return; }
                messageDiv.textContent = '';
                recordsGrid.innerHTML = '';
                result.records.forEach(r => {
                    const el = document.createElement('div');
                    el.className = 'card rounded-2xl p-6 flex flex-col';
                    el.innerHTML = '<div class="flex-grow"><h3 class="text-xl font-bold mb-2">Health Record</h3><p><strong>Notes:</strong> ' + (r.recordData.healthCondition || 'N/A') + '</p></div><button class="share-btn w-full mt-4 bg-blue-600 font-bold py-2 rounded-lg" data-record-hash="' + r.recordHash + '">Share Access</button>';
                    recordsGrid.appendChild(el);
                });
            }
            recordsGrid.addEventListener('click', e => {
                if(e.target.classList.contains('share-btn')) {
                    document.getElementById('recordHashToShare').value = e.target.dataset.recordHash;
                    shareModal.classList.remove('hidden');
                }
            });
            document.getElementById('cancelShare').addEventListener('click', () => shareModal.classList.add('hidden'));
            shareForm.addEventListener('submit', async e => {
                e.preventDefault();
                const msgDiv = document.getElementById('shareMessage');
                const recordHash = document.getElementById('recordHashToShare').value;
                const shareWithEmail = document.getElementById('shareWithEmail').value;
                msgDiv.textContent = 'Processing...';
                try {
                    const addrRes = await fetch('/api/users/eth-address/' + shareWithEmail);
                    const addrResult = await addrRes.json();
                    if (!addrResult.success) throw new Error(addrResult.message);
                    msgDiv.textContent = 'Please approve transaction in MetaMask...';
                    const provider = new ethers.providers.Web3Provider(window.ethereum);
                    await provider.send("eth_requestAccounts", []);
                    const signer = provider.getSigner();
                    const contract = new ethers.Contract(contractAddress, contractABI, signer);
                    const tx = await contract.grantAccess(recordHash, addrResult.ethAddress);
                    await tx.wait();
                    msgDiv.textContent = 'Access granted successfully!';
                    setTimeout(() => shareModal.classList.add('hidden'), 2000);
                } catch (err) { msgDiv.textContent = 'Error: ' + (err.reason || err.message); }
            });
            loadRecords();
        });
    </script></body></html>`);
});


// -----------------------------------------------------------
// START SERVER
// -----------------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log(`Timestamp: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`);
    console.log(`Location: Coimbatore, Tamil Nadu, India`);
});