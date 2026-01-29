
<?php
include 'conn.php'; // include your database connection

// Get mobile number from shonu_subjects
$sql = "SELECT mobile FROM shonu_subjects LIMIT 1"; // Adjust if needed
$result = $conn->query($sql);

$mobile = "";
if ($result && $row = $result->fetch_assoc()) {
    $mobile = $row['mobile'];
}
?>
<html lang="en" translate="no" data-dpr="1" style="font-size: 40.5px;"><head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <link rel="shortcut icon" href="/images/bitbug_favicon.ico" type="image/x-icon">
    <meta name="google" content="notranslate">
    <meta name="robots" content="noindex,nofollow">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  
  
    <meta content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no" name="viewport">
    <title>OrangeClub Official</title>
    <link rel="icon" href="/favicon.ico">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="./css/_vite_template-88676b31.css">
    <link rel="stylesheet" href="./css/index-3cf8aaa6.css">
    <link rel="stylesheet" href="./css/index-8d0b9742.css">
    <link rel="stylesheet" href="./css/index-d27f4bf1.css">
    <link rel="stylesheet" href="./css/NavBar-c40aa6d4.css">
    <link rel="stylesheet" href="./css/index-dc81589f.css">
  
    <style>
      .fun-tabs {
  
        background: #22275b !important;
      }
  
      .fun-tabs {
        overflow: auto !important;
        position: relative;
        width: 100%;
      }
  
      .luckyWinners__container {
        padding: 0.4rem !important;
      }
  
      .dailyProfitRank {
        padding: 0.3rem;
      }
  
      .terms {
        padding: 0.5rem !important;
      }
  
      .settingPanel__container.panel-daman {
        padding: 0.5rem !important;
      }
  
      .tab_item {
        background: #2b3270;
      }
  
      .onlineGames__container[data-v-6dbd07ea] .tabs .tab_item {
  
        height: 1.53333rem !important;
  
      }
  
      .settingPanel__container-items {
        margin-bottom: 3.5rem;
      }
    </style>
  
  </head>
  <!-- Dialog HTML -->
  
  
  <body style="font-size: 12px;" class="">
  
    <div id="app" data-v-app="">
  
      <!---->
      
      <div data-v-6dbd07ea="" class="onlineGames__container" style="--f817f0ee: 'Roboto', 'Inter', sans-serif;background: #fff;">
        <div data-v-81ead1cb="" data-v-6dbd07ea="" class="navbar">
          <div data-v-81ead1cb="" class="navbar-fixed wc" class="navbar-fixed wc" style="background: linear-gradient(90deg, #f95959 0%, #ff9a8e 100%);height: 44px;px; */line-height: 44px;">
            <div data-v-81ead1cb="" class="navbar__content">
              <div data-v-81ead1cb="" class="navbar__content-left" onclick="location.href='/'">
                <i data-v-81ead1cb="" class="van-badge__wrapper van-icon van-icon-arrow-left">
                  <!---->
                  <!---->
                  <!---->
                </i>
              </div>
              <div data-v-81ead1cb="" class="navbar__content-center">
                <!---->
                <span data-v-6dbd07ea="" class="">
                  All Game
                </span>
                <input data-v-6dbd07ea="" type="text" placeholder="Search game" class="">
              </div>
              <div data-v-81ead1cb="" class="navbar__content-right">
                <i data-v-6dbd07ea="" class="van-badge__wrapper van-icon">
                  <!---->
                  <img data-v-11ffe290="" data-v-106b99c8="" src="./assets/audio (1).webp"onclick="location.href='https://telegram.me/orangeclub_official'" style="width:.66667rem;height:.66667rem">
                  <!---->
                </i>
  
              </div>
            </div>
          </div>
        </div>
        <div data-v-6dbd07ea="">
  
            <div data-v-6dbd07ea="" class="fun-tabs tabs">
                <div class="fun-tabs__tab-list"
                  style="transition-timing-function: cubic-bezier(0.1, 0.57, 0.1, 1);transition-duration: 0ms;transform: translate3d(0px, 0px, 0px);display: none;">
                  <div class="fun-tab-item funtab_item">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <a data-v-6dbd07ea="" class="tab_item  tab_active" href="./crash">
                          <img data-v-6dbd07ea="" src="./assets/png/JILIActive-ff37a95a.png">
                          <span data-v-6dbd07ea="">
                            Crash game
                          </span>
                        </a>
                      </div>
                      <!--v-if-->
                    </div>
                  </div>
                  <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <a class="fun-tab-item__label" href="./fishing">
                        <div data-v-6dbd07ea="" class="tab_item" >
                          <img data-v-6dbd07ea="" src="./assets/png/PG-a574cdcc.png">
                          <span data-v-6dbd07ea="">
                            Fishing
                          </span>
                        </div>
                      </a>
                      <!--v-if-->
                    </div>
                  </div>
                  <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <a href="./rummy" data-v-6dbd07ea="" class="tab_item" >
                          <img data-v-6dbd07ea="" src="./assets/png/AG-1c935333.png">
                          <span data-v-6dbd07ea="">
                            Rummy
                          </span>
                        </a>
                      </div>
                      <!--v-if-->
                    </div>
                  </div>
                  <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <a href="./slot" data-v-6dbd07ea="" class="tab_item">
                          <img data-v-6dbd07ea="" src="./assets/png/MG-e0fa50f7.png">
                          <span data-v-6dbd07ea="">
                            Slot
                          </span>
                        </a>
                      </div>
                      <!--v-if-->
                    </div>
                  </div>
                  <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <a href="./casino" data-v-6dbd07ea="" class="tab_item">
                          <img data-v-6dbd07ea="" src="./assets/png/JDB-8224bc9c.png">
                          <span data-v-6dbd07ea="">
                            Casino
                          </span>
                        </a>
                      </div>
                      <!--v-if-->
                    </div>
                  </div>
                  <!-- <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <div data-v-6dbd07ea="" class="tab_item" onclick="location.href='/slotcq9'">
                          <img data-v-6dbd07ea="" src="/assets/png/CQ9-9faff6b9.png">
                          <span data-v-6dbd07ea="">
                            CQ9
                          </span>
                        </div>
                      </div>
                     
                    </div>
                  </div>
                  <div class="fun-tab-item funtab_item" style="">
                    <div class="fun-tab-item__wrap">
                      <div class="fun-tab-item__label">
                        <div data-v-6dbd07ea="" class="tab_item" onclick="location.href='/slotevo'">
                          <img data-v-6dbd07ea="" src="/assets/png/EVO-af7bbdd1.png">
                          <span data-v-6dbd07ea="">
                            EVO_Electronic
                          </span>
                        </div>
                      </div>
                   
                    </div>
                  </div> -->
      
                </div>
              </div>
          <div data-v-6dbd07ea="" class="fun-tabs tab-type"style="display: none;">
            <div class="fun-tabs__tab-list" style="transition-timing-function: cubic-bezier(0.1, 0.57, 0.1, 1); transition-duration: 0ms; transform: translate3d(0px, 0px, 0px);">
              <div class="fun-tabs__active-line" style="transition: all 300ms ease 0s; width: 0px; height: 3px; transform: translate3d(0px, 0px, 0px); background-color: rgb(22, 119, 255);">
              </div>
            </div>
          </div>
          <div data-v-6dbd07ea="">
            <div data-v-03087118="" data-v-2195e495="" style="margin: 5px;" class="daman__container allGame">
            <div data-v-03087118="" class="item" onclick="openDialog(2)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/2.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(4)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/4.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(5)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/5.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(6)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/6.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(9)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/9.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(10)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/10.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(13)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/13.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(14)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/14.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(16)">
              <img data-v-03087118="" class="gameImg" src="/assets/SLOT_GAME/16.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(17)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/17.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(21)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/21.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(23)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/23.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(26)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/26.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(27)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/27.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(30)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/30.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(33)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/33.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(35)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/35.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(36)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/36.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(37)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/37.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(38)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/38.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(40)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/40.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(43)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/43.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(44)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/44.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(45)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/45.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(46)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/46.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(47)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/47.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(48)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/48.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(49)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/49.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(51)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/51.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(58)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/58.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(60)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/60.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(67)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/67.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(76)">
              <img data-v-03087118="" class="gameImg" src="/assets/SLOT_GAME/76.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(77)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/77.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(78)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/78.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(85)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/85.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(87)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/87.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(91)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/91.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(92)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/92.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(100)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/100.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(101)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/101.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(102)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/102.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(103)">
              <img data-v-03087118="" class="gameImg" src="/assets/SLOT_GAME/103.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(106)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/106.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(108)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/108.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(109)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/109.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(110)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/110.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(115)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/115.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(116)">
              <img data-v-03087118="" class="gameImg" src="/assets/SLOT_GAME/116.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(126)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/126.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(130)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/130.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(134)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/134.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(135)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/135.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(136)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/136.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(137)">
              <img data-v-03087118="" class="gameImg" src="/assets/SLOT_GAME/137.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(142)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/142.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(144)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/144.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(145)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/145.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(146)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/146.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(153)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/153.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(164)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/164.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(166)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/166.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(171)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/171.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(172)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/172.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(176)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/176.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(181)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/181.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(183)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/183.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(191)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/191.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(193)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/193.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(198)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/198.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(200)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/200.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(209)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/209.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(212)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/212.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(214)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/214.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(223)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/223.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(225)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/225.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(230)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/230.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(238)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/238.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(239)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/239.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(252)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/252.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(301)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/301.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(303)">
              <img data-v-03087118="" class="gameImg" src="./assets/SLOT_GAME/303.png" lazy="loaded">
            </div>
 
            <div data-v-03087118="" class="item" onclick="openDialog(224)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/224.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(229)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/229.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(232)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/232.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(233)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/233.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(235)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/235.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(236)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/236.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(241)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/241.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(242)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/242.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(254)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/254.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(261)">
              <img data-v-03087118="" class="gameImg" src="./assets/CRASH_GAME/261.png" lazy="loaded">
            </div>   
             
            <div data-v-03087118="" class="item" onclick="openDialog(72)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/72.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(79)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/79.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(94)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/94.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(127)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/127.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(159)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/159.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(160)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/160.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(161)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/161.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(163)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/163.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(199)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/199.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(211)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/211.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(219)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/219.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(220)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/220.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(221)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/221.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(231)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/231.png"lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(253)">
              <img data-v-03087118="" class="gameImg" src="./assets/jilli/253.png"lazy="loaded">                
            </div>
            
            <div data-v-03087118="" class="item" onclick="openDialog(1)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/1.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(20)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/20.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(32)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/32.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(42)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/42.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(60)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/60.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(71)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/71.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(74)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/74.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(82)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/82.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(119)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/119.png" lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(212)">
              <img data-v-03087118="" class="gameImg" src="./assets/FISH_GAME/212.png" lazy="loaded">
            </div>  
            <div data-v-03087118="" class="item" onclick="openDialog(111)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/111.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(112)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/112.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(113)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/113.png"
                lazy="loaded">
            </div>

            <div data-v-03087118="" class="item" onclick="openDialog(118)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/118.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(112)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/122.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(123)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/123.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(124)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/124.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(125)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/125.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(139)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/139.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(148)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/148.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(149)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/149.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(150)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/150.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(151)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/151.png"
                lazy="loaded">
            </div>

            <div data-v-03087118="" class="item" onclick="openDialog(152)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/152.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(173)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/173.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(177)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/177.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(178)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/178.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(179)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/179.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(182)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/182.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(195)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/195.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(197)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/197.png"
                lazy="loaded">
            </div>

            <div data-v-03087118="" class="item" onclick="openDialog(200)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/200.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(204)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/204.png"
                lazy="loaded">
            </div>
            <div data-v-03087118="" class="item" onclick="openDialog(217)">
              <img data-v-03087118="" class="gameImg" src="./assets/TABLE_GAME_CASINO/217.png"
                lazy="loaded">              
            </div>            
            </div>

            <!---->
          </div>
        </div>
      </div>
    </div>

    <!---->
    <!---->
    <!---->
    <!---->
    <!---->
    <!---->
    <!---->
    <!---->
    <!---->
  
  
  
  
  
  
  
  
  
  
  
  
  
  
    </div>
    <div data-v-app="">
    </div>
    <div class="van-overlay" id="gameconfirmoverlay" style="z-index: 2001; display: none;"></div>
  <div role="dialog" tabindex="0" id="gameconfirm" class="van-popup van-popup--center van-dialog gameDialog" style="z-index: 2001; display: none;" aria-labelledby="Tips">
      <div class="van-dialog__header" style=" border-bottom: 1px solid #ccc;">Tips</div>
      <div class="van-dialog__content" style="padding: 20px;">
          <div class="van-dialog__message van-dialog__message--has-title">Are you sure you want to join the game?</div>
      </div>
      <div class="van-hairline--top van-dialog__footer" style="padding: 10px;">
          <button type="button" class="van-button van-button--default van-button--large van-dialog__cancel" style="margin-right: 10px;" onclick="closeDialog()">
              <div class="van-button__content"><span class="van-button__text1">Cancel</span></div>
          </button>
          <button type="button" class="van-button van-button--default van-button--large van-dialog__confirm van-hairline--left" onclick="redirectJilliFunction()">
              <div class="van-button__content"><span class="van-button__text1">Confirm</span></div>
          </button>
      </div>
  </div>
      <style>
      .loading-image {
          position: fixed;
          margin-top: -100px;
          top: 60%;
          left: 50%;
          transform: translate(-50%, -50%);
      }
  </style>
  
  <div id="loadingImage" class="loading-image" style="z-index: 2001; display:none;">
      <img src="/images/loading2.gif" alt="Loading..." width="200" height="200">
  </div>
  
  
        
      <link rel="stylesheet" href="https://site-assets.fontawesome.com/releases/v6.5.1/css/all.css">
      <link rel="stylesheet" href="https://site-assets.fontawesome.com/releases/v6.5.1/css/sharp-thin.css">
      <link rel="stylesheet" href="https://site-assets.fontawesome.com/releases/v6.5.1/css/sharp-solid.css">
      <link rel="stylesheet" href="https://site-assets.fontawesome.com/releases/v6.5.1/css/sharp-regular.css">
      <link rel="stylesheet" href="https://site-assets.fontawesome.com/releases/v6.5.1/css/sharp-light.css">
      <link rel="stylesheet" href="/index_files/index-96409872.css"> 
      <link rel="stylesheet" href="../assets/css/index-3cf8aaa6.css"> 
  
  <style>
      .block-click {
          pointer-events: none;  
      }
  
      .tabbar__container-item[data-v-76c247f8]:nth-of-type(3) svg {
      position: absolute;
      bottom: 0.8rem !important;
      width: 0.86667rem !important;
      height: 0.86667rem !important;
      z-index: 3;
  }
  </style>
<script>
  const phoneUserUid = "<?php echo $mobile; ?>";

  function openDialog(gameId) {
    if (!phoneUserUid || phoneUserUid.length < 5) {
      alert("Mobile number load nahi ho paya. Try again.");
      return;
    }

    const url = `https://allapi.shivwin.in/post?gameId=${gameId}&mobile=1234567890&agentId=tringa_Seamless&agentKey=16f11f76756d74471283ab71b5eccb72fe339538&referrerUrl=https://pay.tirangakings.com/jili.php`;
    window.location.href = url;
  }
</script>



  
  </body></html>