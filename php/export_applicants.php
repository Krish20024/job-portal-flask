<?php
// Usage (CLI or web): export_applicants.php?job_id=1
$job_id = isset($_GET['job_id']) ? intval($_GET['job_id']) : 0;
if ($job_id <= 0) { http_response_code(400); echo "Missing job_id"; exit; }

// Path to the same SQLite DB used by Flask
$dbPath = realpath(__DIR__ . "/../instance/job_portal.db");
if (!$dbPath) { http_response_code(500); echo "DB not found"; exit; }

try {
  $pdo = new PDO("sqlite:" . $dbPath);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $stmt = $pdo->prepare("
    SELECT a.id, u.name AS student_name, u.email, a.cover_note, a.status, a.applied_at
    FROM applications a
    JOIN users u ON u.id = a.student_id
    WHERE a.job_id = :job_id
    ORDER BY a.applied_at DESC
  ");
  $stmt->execute([':job_id' => $job_id]);

  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename=applicants_job_' . $job_id . '.csv');

  $out = fopen('php://output', 'w');
  fputcsv($out, ['ApplicationID','StudentName','Email','CoverNote','Status','AppliedAt']);
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    fputcsv($out, $row);
  }
  fclose($out);
} catch (Exception $e) {
  http_response_code(500);
  echo "Error: " . htmlspecialchars($e->getMessage());
}