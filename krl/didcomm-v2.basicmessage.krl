ruleset didcomm-v2.basicmessage {
  meta {
    name "BasicMessage"
    description <<
      Implements the basicmessage protocol
      https://didcomm.org/basicmessage/2.0/
    >>
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did-o alias dcv2
  }
  global {
    bmTags = ["didcomm-v2","basicmessage"] // meta:rid.split(".")
    generate_basicmessage = function(their_did,message_text,thid){
      dido:generateMessage({
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "from": dcv2:didMap(){their_did},
        "to": [their_did],
        "thid": thid,
        "body": {
          "content": message_text,
        }
      })
    }
  }
  rule initializeOnInstallation {
    select when wrangler ruleset_installed where event:attrs{"rids"} >< meta:rid
    pre {
      route0 = dcv2:addRoute("https://didcomm.org/basicmessage/2.0/message",
                 "didcomm_v2_basicmessage", "message_received")
    }
    wrangler:createChannel(
      bmTags,
      {"allow":[{"domain":"didcomm_v2_basicmessage","name":"*"}],"deny":[]},
      {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
    )
    fired {
      raise didcomm_v2_basicmessage event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when didcomm_v2_basicmessage factory_reset
    foreach wrangler:channels(bmTags).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
  rule incomingMessge {
    select when didcomm_v2_basicmessage message_received
    pre {
      message = event:attrs{"message"}
    }
  }
  rule outgoingMessage {
    select when didcomm_v2_basicmessage message_to_send
    pre {
      their_did = event:attrs{"their_did"}
      message_text = event:attrs{"message_text"}
      thid = event:attrs{"thid"}
      message = generate_basicmessage(their_did,message_text,thid)
      a = dcv2:send(their_did,message)
    }
    fired {
      raise didcomm_v2_basicmessage event "message_sent" attributes{
        "message": message
      }
    }
  }
}
