<?php
require_once '../simwood.php';

$ip = Simwood::get_instance()->get_my_ip();

echo $ip;