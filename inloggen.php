<?php
// Start de sessie
session_start();

// Verbinding maken met de database
$host = 'localhost';
$dbname = 'login_system';
$dbuser = 'root';
$dbpass = '';

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $dbuser, $dbpass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Gegevens ontvangen uit het formulier
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim($_POST['username']);
    $pass = trim($_POST['password']);

    if (empty($user) || empty($pass)) {
        $_SESSION['error'] = "Gebruikersnaam en wachtwoord mogen niet leeg zijn.";
        header("Location: index.html");
        exit;
    }

    // Zoeken naar de gebruiker in de database
    $sql = "SELECT password FROM users WHERE username = :username";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':username', $user);
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    $loginSuccess = false;

    if ($result && password_verify($pass, $result['password'])) {
        // Succesvolle login
        $loginSuccess = true;
        $_SESSION['error'] = ''; // Leegmaken van foutmelding bij succesvolle login
    } else {
        $_SESSION['error'] = "Ongeldige gebruikersnaam of wachtwoord.";
    }

    // Opslaan van login poging in login_attempts tabel
    $sqlInsert = "INSERT INTO login_attempts (username, password_attempt, login_success) 
                  VALUES (:username, :password_attempt, :login_success)";
    $stmtInsert = $conn->prepare($sqlInsert);
    $stmtInsert->bindParam(':username', $user);
    $stmtInsert->bindParam(':password_attempt', $pass); // Optioneel: je kunt een hash van het wachtwoord opslaan voor privacy
    $stmtInsert->bindParam(':login_success', $loginSuccess, PDO::PARAM_BOOL);

    // Redirect naar index.html
    header("Location: index.html");
    exit;
}
?>
