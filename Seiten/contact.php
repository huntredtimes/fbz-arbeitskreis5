<!DOCTYPE html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Kontaktieren Sie uns! (9)</title>
    <link rel="stylesheet" href="stylesheet.css"> 
  </head>
  <body>
    <?php
      use PHPMailer\PHPMailer\PHPMailer;
      use PHPMailer\PHPMailer\Exception;
    
      require 'php_mailer/PHPMailer-6.5.1/src/Exception.php';
      require 'php_mailer/PHPMailer-6.5./src/PHPMailer.php';
      require 'php_mailer/PHPMailer-6.5./src/SMTP.php';
      if(isset($_POST["submit"])){
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->Host = "smtp.gmail.com";
        $mail->SMTPAuth = true;
        $mail->Username = "fbz.ak5.iud@gmail.com";
        $mail->Password = "sxpeuyczbllrabof";

        $mail->setFrom("fbz.ak5.iud@gmail.com", "FBZ e.V., AK5"); 
        
        $mail->Subject = "Test";
        $mail->Body = $_POST["msg"];

        if($mail->send()){
          echo "Deine Email wurde verschickt.";
        } else{
          echo "Es gab einen Fehler".$mail->ErrorInfo;
        }

      }
    ?>
    <div id="container">
    <div id="top"> 
      <a href="index.html">Home</a>
      <!--<a href="about.html">Über uns</a>-->
      <a href="digitalerzwilling.html">Digitale Zwillinge</a>
      <a href="projektkoop.html">Forschung & Nachwuchs</a>
      <a id="contact" href="contact.html">Kontakt</a>
    </div>
    <div id="header"> 
      <h1>Innovation und Digitalisierung</h1>
      <p class="untertitel">Arbeitskreis des FBZ e.V., An- Institut der Hochschule Merseburg</p>
    </div>  
    <div class="textcontent" style="height: fit-content;">
      <form method="post" action="contact.php">
        <textarea name="msg" placeholder="Nachricht"></textarea><br>
        <button type="submit" name="submit">Senden</button>
      </form>
    </div>
     <!--
    <div class="textcontent"> 
      <p class="bezeichner">ÜBER UNS</p>
      <p class="lauftext"> 
        Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.
        <div style="text-align: center; padding-top: 100px;"><a id="contact2" href="contact.html">Kontaktieren Sie uns!</a>
        </div></p> 
    </div>  -->
    <div id="bottom"> 
      <a id="bottom" href="impressum.html">Impressum</a> |
      <a id="bottom"href="datenschutz.html">Datenschutz</a> 
      <p>© 2021 FBZ e.V., Ak "IuD"</p>
    </div>
    </div>
  </div>
  </body>
</html>