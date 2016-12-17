var myNotificationID = null;
var currentTab = null;
var clientId = null;
var DEBUG = true;
var SAFE = "safe";
var MALICIOUS = "malicious";

var REST_URL = ""


var localCache = {};

function sendImageAync(image, queryUrl, callback) {
  var url = REST_URL + ":5001/check";

  var domain = queryUrl.hostname
  image = image.replace(/^data:image\/(png|jpg|jpeg);base64,/, "");
  $.ajax({
    url:url,
    data:JSON.stringify({'img_data':image, 'domain':domain, 'url':queryUrl.href}),
    type:"POST",
    contentType:"application/json",
    success:callback
  });
}

/**
* Safe domain to local safe cache
**/
function saveSafe(domain, callback) {
  localCache[domain] = SAFE;
  chrome.storage.local.set(localCache, callback);
}

/**
* Safe domain to local malicious cache
**/
function saveMalicious(domain, callback) {
  localCache[domain] = MALICIOUS;
  chrome.storage.local.set(localCache, callback);
}

function getCache(domain, callback) {
  chrome.storage.local.get(localCache, function(response) {
    callback(response[domain]);
  });
}

function sendSafeAsync(callback) {
  var url = REST_URL + ":5001/safe";
  $.ajax({
    url:url,
    data:JSON.stringify({'clientId':clientId, 'url':currentTab.url}),
    type:"POST",
    contentType:"application/json",
    success:callback
  });
  
}

function createNotification(options) {
  chrome.notifications.create(
      "",
      options,
      function(id) {
        myNotificationID = id;
    });
}

function maliciousPageWarning() {
  var opt = {
    type: "basic",
    title: "Warning",
    message: "This site seems to be trying to mimick a site that it's really not.",
    iconUrl: "media/error-80.png",
    buttons: [
      {title: "Get me out of here!"},
      {title: "No, this site seems fine."}
    ]
  }

  if(myNotificationID == null ) {
    createNotification(opt);

  } else {
    chrome.notifications.clear(myNotificationID, function () {
      createNotification(opt);
    });
  }
  
}

function redirect() {
  chrome.tabs.update(currentTab.id,
  {
    url: "http://www.google.com/"
  });
}

/**
* Handle click events to the warning notification
**/
chrome.notifications.onButtonClicked.addListener(function(notifId, btnIdx) {
    if (notifId === myNotificationID) {
      url = currentTab.url;
        if (btnIdx === 0) {
          redirect();

          saveMalicious(url, function() {
            if (DEBUG)
              chrome.extension.getBackgroundPage().console.log("local: malicious" + clientId);
          });
        } else if (btnIdx === 1) {
            sendSafeAsync(function () {
              if (DEBUG)
                chrome.extension.getBackgroundPage().console.log("remote: safe" + clientId);
            });

            saveSafe(url, function() {
              if (DEBUG)
                chrome.extension.getBackgroundPage().console.log("local: safe" + clientId);
            });
        }

        chrome.notifications.clear(notifId, function () {
          myNotificationID = null;
        });
    }
});

/**
* Analyze site upon finished page load
**/
chrome.tabs.onUpdated.addListener( function (tabId, changeInfo, tab) {
  if (changeInfo.status == 'complete') {
    currentTab = tab;
    var url = new URL(tab.url)

    //First check cache
    getCache(url, function(response) {
      if(response != null && response == SAFE) {

      } else if (response != null && response == MALICIOUS) {
        maliciousPageWarning();
      } else { // URL isn't in cache
        //Capture page
        chrome.tabs.captureVisibleTab(function(screenshot) {
          if(screenshot != null) {
            screenshot  = screenshot.replace("data:image/png;base64,", "");
            //Send page for analysis
            sendImageAync(screenshot, url, function(response) {
              if(response != "False"){
                if(DEBUG)
                  chrome.extension.getBackgroundPage().console.log(url);
                clientId = response;
                maliciousPageWarning();
              }else {
                if(DEBUG)
                  chrome.extension.getBackgroundPage().console.log("false");
    
                saveSafe(url, function() {
                  if (DEBUG)
                    chrome.extension.getBackgroundPage().console.log("local: safe");
                });
              }
            });
          }
        });
      }
    });
  }
})

