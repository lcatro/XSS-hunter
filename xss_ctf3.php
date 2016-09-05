
<?php
    if (isset($_POST['Comment'])) {
        if (strstr($_POST['Comment'],'<script>') && strstr($_POST['Comment'],'</script>')) {
            echo '<script>alert("success");</script>';
        } else {
            $comment_data='<br/><br/>'.$_POST['Comment'];
            $comment_file=fopen('./data.txt','a');
            fwrite($comment_file,$comment_data);
            fclose($comment_file);
        }
    }
?>

<html>
    <body>
        <div id="output_window">
            <?php
                $comment_data=file_get_contents('./data.txt');
                echo $comment_data;
            ?>
        </div>
        <form method="post">
            Comment:<input type="text" name="Comment"/><br/>
            <input type="submit"/>
        </form>
    </body>
</html>
