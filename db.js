require("dotenv").config();
const { initializeApp, applicationDefault } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

initializeApp({
    credential: applicationDefault(), // Lee la clave privada desde la variable de entorno
});

const db = getFirestore();

module.exports = { db };
