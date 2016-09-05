<?php

if (isset($_GET['keyword'])) {
    if (strstr($_GET['keyword'],'<script>') && strstr($_GET['keyword'],'</script>'))
        echo '<script>alert("success");</script>';
	echo '<br/><br/>'.$_GET['keyword'];
} else {
	echo '<script>window.location.href="xss_ctf1.php?keyword=123";</script>';
}

?>