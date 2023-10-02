ruleset didcomm-v2.user-profile {
  meta {
    name "User Profile"
    description <<
      Implements the user-profile protocol
      https://didcomm.org/user-profile/1.0/
    >>
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did-o alias dcv2
  }
  global {
    upTags = ["didcomm-v2","user-profile"] // meta:rid.split(".")
    generate_basicmessage = function(their_did,message_text,thid){
      dido:generateMessage({
        "type": "https://didcomm.org/user-profile/1.0/profile",
        "from": dcv2:didMap(){their_did},
        "to": [their_did],
        "thid": thid,
        "body": {
          "profile": {
            "displayName": pds:getName(),
          },
        }
      })
    }
  }
  rule initializeOnInstallation {
    select when wrangler ruleset_installed where event:attrs{"rids"} >< meta:rid
    pre {
      route0 = dcv2:addRoute("https://didcomm.org/user-profile/1.0/profile",
                 "didcomm_v2_user_profile", "profile_received")
      route2 = dcv2:addRoute("https://didcomm.org/user-profile/1.0/request-profile",
                 "didcomm_v2_user_profile", "request_profile_received")
    }
    wrangler:createChannel(
      upTags,
      {"allow":[{"domain":"didcomm_v2_user_profile","name":"*"}],"deny":[]},
      {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
    )
    fired {
      raise didcomm_v2_user_profile event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when didcomm_v2_user_profile factory_reset
    foreach wrangler:channels(upTags).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
}
