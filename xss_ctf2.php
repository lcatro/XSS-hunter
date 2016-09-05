
<?php
    if (isset($_POST['username']) && isset($_POST['username'])) {
        if (strstr($_POST['username'],'<script>') && strstr($_POST['username'],'</script>'))
            echo '<script>alert("success");</script>';
        if (strstr($_POST['password'],'<script>') && strstr($_POST['password'],'</script>'))
            echo '<script>alert("success");</script>';
    }
?>

<html>
    <body>
        <form method="post">
            Username:<input type="text" name="username" value="<?php if (isset($_POST['username'])) echo $_POST['username']; ?>" /><br/>
            Password:<input type="text" name="password" value="<?php if (isset($_POST['password'])) echo $_POST['password']; ?>" /><br/>
            <input type="submit"/>
        </form>
    </body>
</html>
