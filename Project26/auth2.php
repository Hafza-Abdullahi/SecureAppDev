<?php
	include_once 'header.php';
	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	} else {
		$user_id = $_SESSION['u_id'];
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 2</h2>
				<?php
				$ViewFile = $_GET['FileToView'];

				// Strip out all directory traversal characters (../) 
				$safe_file = basename($ViewFile);
     
				if(file_exists($safe_file))    
				{
					$FileData = file_get_contents($safe_file);
					echo htmlspecialchars($FileData, ENT_QUOTES, 'UTF-8');
				}
				else
				{
					echo "no file found";
				}
?>
            </div>
        </section>

<?php
	include_once 'footer.php';
?>