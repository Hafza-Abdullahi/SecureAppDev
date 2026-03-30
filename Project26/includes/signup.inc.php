<?php

    if (isset($_POST['submit'])) {

        session_start();
        include_once 'dbh.inc.php';

        $uid = $_POST['uid'];
        $pwd = $_POST['pwd'];

        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
        } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }
          else {
            $ipAddr=$_SERVER['REMOTE_ADDR'];
        }

        //CHECK IF USER IS LOCKED OUT
        $checkClient = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result(); 
        
        // keep track of failed login attempts for this IP and lock them out if they have 5 or more within the last 3 minutes
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $failedLoginCount = $row['failedLoginCount'];
            $failedLoginTime = $row['timeStamp'];
            
            // If they have 5 or more attempts, check how long it's been since their last attempt
            if ($failedLoginCount >= 5) {
                $currTime = date("Y-m-d H:i:s");
                $timeDiff = abs(strtotime($currTime) - strtotime($failedLoginTime));
                
                // user gets kicked out after 5 failed attempts within 3 minutes
                if((int)$timeDiff <= 180) { 
                    $secondsLeft = 180 - $timeDiff;
                    $_SESSION['register'] = "Error: Too many requests. Please wait " . $secondsLeft . " seconds.";
                    header("Location: ../index.php");
                    exit();
                }
            }
        }

        /* OLD CODE 
        //CHECK IF USER IS LOCKED OUT
        $checkClient = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result(); 
        if ($result->fetch_row()[0] == 5) {
            $_SESSION['register'] = "Error: locked out.";
            header("Location: ../index.php");
            exit();
        } */
        
        // Check for empty fields
        if (empty($uid) || empty($pwd)) {
            $_SESSION['register'] = "Cannot submit empty username or password.";
            header("Location: ../index.php");
            exit();

        } else {

            //Check to make sure only alphabetical characters are used for the username
            if (!preg_match("/^[a-zA-Z]*$/", $uid)) {

                $_SESSION['register'] = "Username must only contain alphabetic characters.";
                header("Location: ../index.php");
                exit();

            } else {
				
                    $sql = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("s", $uid);
                    $stmt->execute();
                    $result = $stmt->get_result();

					//If the user already exists, prevent them from signing up
                    if ($result->num_rows > 0) {

                        $_SESSION['register'] = "Error.";
                        header("Location: ../index.php");
                        exit();

                    } else {
                        $hashedPWD = $pwd;

                        $sql = "INSERT INTO `sapusers` (`user_uid`, `user_pwd`) VALUES (?, ?)"; 
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("ss", $uid, $hashedPWD);
                        
                        if(!$stmt->execute()) {
                            echo "Error: " . $stmt->error;
                        }

                        $_SESSION['register'] = "You've successfully registered as " . $uid . ".";

                        // Update spam counter to avoid infinite acc creation
                        $currTime = date("Y-m-d H:i:s");
                        $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?"; 
                        $stmtCount = $conn->prepare($updateCount);
                        $stmtCount->bind_param("ss", $currTime, $ipAddr);
                        $stmtCount->execute();

                        header("Location: ../index.php");
                        exit();

                    }
                }   
        }
    }