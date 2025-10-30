<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

class Expression {
    public $Expressionop;
    public $Expressionparams;
    public $stringify;

    public function __construct($op = "", $params = [], $stringify = "") {
        $this->Expressionop = $op;
        $this->Expressionparams = $params;
        $this->stringify = $stringify;
    }

    public function __wakeup() {
        if (function_exists($this->Expressionop)) {
            ob_start();
            call_user_func_array($this->Expressionop, (array) $this->Expressionparams);
            $this->stringify = ob_get_clean(); // Capture command output
        } else {
            $this->stringify = "Invalid operation";
        }
    }
}

$sumResult = null;
$generatedToken = null;

// Handle deserialization when a token is provided
if (isset($_GET['token'])) {
    $data = base64_decode($_GET['token']);
    $obj = unserialize($data);
    $sumResult = $obj->stringify ?? "Invalid token";
}

// Handle form submission to generate a token
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['num1']) && isset($_POST['num2'])) {
    $num1 = (int) $_POST['num1'];
    $num2 = (int) $_POST['num2'];
    $sum = $num1 + $num2;

    // Create a serialized token for sum calculation
    $expression = new Expression("sum", [$num1, $num2], "$num1 + $num2 = $sum");
    $serialized = serialize($expression);
    $generatedToken = base64_encode($serialized);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Object Injection CTF</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #333; }
        form { margin-bottom: 20px; }
        input[type="number"] { padding: 5px; }
        input[type="submit"] { padding: 10px 20px; background-color: #4CAF50; color: white; border: none; }
        .output { margin-top: 20px; font-weight: bold; color: #007BFF; }
        .token { margin-top: 20px; background: #f4f4f4; padding: 10px; border-left: 5px solid #4CAF50; word-wrap: break-word; }
    </style>
</head>
<body>

<h2>rzx FYP project <3<3<3<3<3</h2>
<p>sometime maybe good sometime maybe sheet.</p>

<form method="POST">
    <label for="num1">Enter first number:</label>
    <input type="number" name="num1" id="num1" required>
    <br><br>
    <label for="num2">Enter second number:</label>
    <input type="number" name="num2" id="num2" required>
    <br><br>
    <input type="submit" value="Calculate">
</form>

<?php if ($sumResult !== null): ?>
    <div class="output"><?= htmlspecialchars($sumResult) ?></div>
<?php endif; ?>

<?php if ($generatedToken !== null): ?>
    <div class="token">Generated Token: <code><?= htmlspecialchars($generatedToken) ?></code></div>
    <p>Use this token: <a href="?token=<?= htmlspecialchars($generatedToken) ?>">Click here</a></p>
<?php endif; ?>

</body>
</html>

