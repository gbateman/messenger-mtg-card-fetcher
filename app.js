/*
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  rp = require('request-promise');

var app = express();
app.set('port', process.env.PORT || 5000);
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN)) {
  console.error('Missing config values');
  process.exit(1);
}

/*
 * Privacy Policy because fb wants that for some reason
 *
 */
app.get('/privacy-policy', function(req, res) {
  res.send('MTGCardFetcher does not request any personal logins or data and therefore does not guarantee the safety of any user data.');
});

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log('Validating webhook');
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error('Failed validation. Make sure the validation tokens match.');
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  console.log("Post to /webhook");
  console.log(JSON.stringify(data));

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else {
          console.log('Webhook received unused messagingEvent: ', messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});


/*
 * Calls the FB attachment upload api and returns an attachment id given a scryfall image link
 *
 */
app.post('/upload', function(req, res) {
  const data = req.body;

  console.log(req);

  if (!data.url) {
    res.status(400).send('Malformed request');
    return;
  }

  if (!data.url.startsWith('https://img.scryfall.com')) {
    res.status(400).send('Not scryfall image');
    return;
  }

  callAttachmentUploadAPI(data.url)
  .then(aid => res.json({ 'attachment_id': aid }))
  .catch(error => res.status(500).send('Failed to contact Facebook upload API'));
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers['x-hub-signature'];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error('Couldn\'t validate the signature.');
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error('Couldn\'t validate the request signature.');
    }
  }
}

/*
 * Message Event
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log('Received message for user %d and page %d at %d with message:',
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  // You may get a text or attachment but not both
  var messageText = message.text;
  if (messageText) {
    handleMessageText(senderID, messageText);
  }
}

/*
 * Postback Event
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var postback = event.postback;

  console.log('Received postback for user %d and page %d at %d with message:',
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(postback));

  var payload = postback.payload;
  if (payload) {
    handleMessageText(senderID, payload);
  }
}

function handleMessageText(senderID, messageText) {
  messageText = messageText.replace(/‘|’/g, '\'').replace(/“|”/g, '\"')
  const hashtagIndex = messageText.indexOf('#');
  let page = 0;
  if (hashtagIndex >= 0 && messageText.length > hashtagIndex) {
    page = parseInt(messageText.substr(hashtagIndex + 1));
    messageText = messageText.substr(0, hashtagIndex);
  }

  callScryfallAPI(senderID, messageText, page);
}

/*
 * Send a message with a card image using the Send API
 *
 */
function callScryfallAPI(recipientId, cardName, page) {
  let options = {
    uri: 'https://api.scryfall.com/cards/search',
    qs: {
      order: 'set',
      dir: 'desc',
      page: 1,
      q: cardName
    },
    method: 'GET',
    json: true
  };
  rp(options)
  .then(response => {
    let hasMore = response.hasMore;
    let data = response.data;
    while (hasMore) {
      options.qs.page = options.qs.page + 1
      rp(options)
      .then(response => {
        data.concat(response.data);
        hasMore = response.hasMore;
      })
    }
    return data;
  })
  .then(data => {
    return data.map(card => {
      const object = card.card_faces && !card.image_uris ? card.card_faces[0] : card;
      return {
        id: card.id,
        name: object.name,
        set: card.set,
        type: object.type_line,
        text: object.oracle_text,
        url: card.scryfall_uri,
        imageUrl: object.image_uris.normal,
        number: card.collector_number
      }
    })
  })
  .then(cards => cards.slice(page * 4)) // Remove already displayed cards
  .then(cards => {
    console.log('Cards: ', cards.map(card => card.name));
    if (cards[0]) {
      const matchingName = cards.filter(card => card.name.toLowerCase() == cardName.toLowerCase());
      if (matchingName.length >= 1) {
        cards = [matchingName[0]]; // If the query matches a card name exactly, only take that card
      }
      if (cards.length == 1) {
        callAttachmentUploadAPI(cards[0].imageUrl)
        .then(attachment_id => {
          sendCardMessage(recipientId, attachment_id, cards[0]);
        });
      } else {
        sendCardListMessage(recipientId, cards, cardName, page);
      }
    } else {
      const messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          text: cardName + ' was not found'
        }
      };
      callSendAPI(messageData);
    }
  });
}

/*
 * Send a message with a card image using the Send API
 *
 */
function sendCardMessage(recipientId, attachment_id, card) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'media',
          elements: [
            {
              media_type: 'image',
              attachment_id: attachment_id,
              buttons: [
                getScryfallButtonForCard(card),
                getShareButtonForCard(card)
              ]
            }
          ]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function getShareButtonForCard(card) {
  return {
    type: 'element_share',
    share_contents: {
      attachment: {
        type: 'template',
        payload: {
          template_type:'generic',
          image_aspect_ratio: 'square',
          elements:[
            {
              title: card.name,
              image_url: card.imageUrl,
              default_action: {
                type: 'web_url',
                url: card.url,
              },
              buttons:[
                getScryfallButtonForCard(card)
              ]
            }
          ]
        }
      }
    }
  }
}

function getScryfallButtonForCard(card) {
   return {
     type: 'web_url',
     url: card.url,
     title: 'Scryfall'
   }
}

/*
 * Send a message with a list of potential cards using the Send API
 *
 */
function sendCardListMessage(recipientId, cards, cardName, page) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'list',
          top_element_style: 'compact',
          elements: cards.slice(0, 4).map(card => {
            return {
              title: card.name,
              subtitle: card.type + '\n' + card.text,
              image_url: card.imageUrl,
              'default_action': {
                'type': 'web_url',
                'url': card.url
              },
              buttons: [
                {
                  type: 'postback',
                  title: 'This One',
                  payload: card.name
                }
              ]
            }
          }),
          buttons: []
        }
      }
    }
  };

  if (cards.length > 4) {
    messageData.message.attachment.payload.buttons.push(
      {
        type: 'postback',
        title: 'More',
        payload: cardName + '#' + (page + 1)
      }
    );
  }

  callSendAPI(messageData);
}

/*
 * Call the Attachment Upload API to get an attachment id for an image
 *
 */
function callAttachmentUploadAPI(url) {
  return new Promise((resolve, reject) => {
    rp({
      uri: 'https://graph.facebook.com/v2.6/me/message_attachments',
      qs: { access_token: PAGE_ACCESS_TOKEN },
      method: 'POST',
      json: {
        message: {
          attachment: {
            type: 'image',
            payload: {
              is_reusable: true,
              url: url
            }
          }
        }
      }
    })
    .then(response => resolve(response.attachment_id))
    .catch(error => {
      console.error('Failed calling Attachment Upload API ', error);
      reject(error);
    });
  });
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log('Successfully sent message with id %s to recipient %s',
          messageId, recipientId);
      } else {
      console.log('Successfully called Send API for recipient %s',
        recipientId);
      }
    } else {
      console.error('Failed calling Send API', response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
