// Reemplaza los valores con los datos de tu proyecto de Firebase Google
const firebaseConfig = {
    apiKey: "AIzaSyDv_LBdsXf15Fh6YaulLdc1W0oZ8niiylQ",
    authDomain: "drivo-web-38237.firebaseapp.com",
    projectId: "drivo-web-38237",
    storageBucket: "drivo-web-38237.firebasestorage.app",
    messagingSenderId: "364408325913",
    appId: "1:364408325913:web:6f286e96e5b6ecbd14a788"
};

// Inicializar Firebase (Versión 8 compat para uso directo en navegador)
firebase.initializeApp(firebaseConfig);
const firestoreDB = firebase.firestore();

// Habilitar caché offline nativo de Firestore (Opcional pero recomendado para mayor robustez)
firestoreDB.enablePersistence().catch(function (err) {
    if (err.code == 'failed-precondition') {
        console.warn("Múltiples pestañas abiertas, persistencia offline solo funciona en una.");
    } else if (err.code == 'unimplemented') {
        console.warn("El navegador no soporta persistencia offline de Firestore.");
    }
});