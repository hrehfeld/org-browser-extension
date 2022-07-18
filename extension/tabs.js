const NATIVE_HOST_NAME = 'de.haukerehfeld.chrome_tabs';
const THE_GREAT_SUSPENDER_EXTENSION_ID = 'klbibkeccnjlkjkiokjodocebajanakg';
const TYPE_TAB = 'tab';
const TYPE_BOOKMARK = 'bookmark';
const TYPE_KILL = 'kill';

const browser = chrome;

function tabs_highlight_compat(args) {
	delete args.populate;
	return args;
}


const T = chrome.tabs;
const B = chrome.bookmarks;
const W = browser.windows;
const runtime = chrome.runtime;


function promisify(f,	success) {
	return new Promise(function(resolve) {
		return f(function() {
			resolve(success.apply(this, arguments));
		});
	});
}


function generateUUID() { // Public Domain/MIT
    var d = new Date().getTime();//Timestamp
    var d2 = (performance && performance.now && (performance.now()*1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16;//random number between 0 and 16
        if(d > 0){//Use timestamp until depleted
            r = (d + r)%16 | 0;
            d = Math.floor(d/16);
        } else {//Use microseconds since page-load if supported
            r = (d2 + r)%16 | 0;
            d2 = Math.floor(d2/16);
        }
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}


function url_clean(url) {
	if (url.startsWith('chrome-extension://' + THE_GREAT_SUSPENDER_EXTENSION_ID + '/')) {
		//const getUrlSuspended = 'document.getElementById("gsTopBarUrl").href;';
		//console.log(url);
		var u = new URL(url).hash;
		const uri_param_str = '&uri=';
		url = u.substr(u.indexOf(uri_param_str) + uri_param_str.length);
		//url = chrome.tabs.executeScript(tab.id, { code: getUrlSuspended });
		//T.sendMessage(tab.id, { action: 'requestInfo' }, {}, function(res) { console.log('res' + res); console.log(chrome.runtime.lastError); });
	}
	url = url.split("#")[0];
	return url;
}


function tab_clean(tab) {
	return { url: url_clean(tab.url), title: tab.title.trim(), type: TYPE_TAB, id: tab.id };
}


function get_tabs() {
	return promisify(success => T.query({}, success),
									 tabs => {
										 tabs.forEach(t => t.type = TYPE_TAB);
										 return tabs;
									 });
}


function bookmark_clean(bookmark) {
	return { url: url_clean(bookmark.url), title: bookmark.title.trim(), type: TYPE_BOOKMARK, id: bookmark.id };
}


function get_bookmarks() {
	return promisify(success => B.search({}, success),
									 function(bookmarks) {
										 // ignore folders
										 bookmarks.forEach(b => b.type = TYPE_BOOKMARK);
										 return bookmarks.filter(b => 'url' in b);
									 });
}


function by_url(_url) {
	const url = _url;
	return function (item) { return item.url === url; };
}


async function get_all() {
	return (await get_tabs()).concat(await get_bookmarks());
}

function item_clean(item) {
	if (item.type === TYPE_TAB) {
		return tab_clean(item);
	}
	else {
		return bookmark_clean(item);
	}
}

function item_clean_url(item) {
	item.url = url_clean(item.url);
	return item;
}

function tab_open_(url, resolve) {
	T.create({url: url}, tab => {
		(function go(i) {
			// tab doesn't update, so we need to requery
			T.get(tab.id, tab => {
				if (tab.status !== "complete") {
					console.log('waiting for tab loading ' + i)
					setTimeout(_ => go(i + 1), 100);
				}
				else {
					console.log('returning tab' + i);
					console.log(tab);
					// not cleaned, this is the internal function and callers might need internal info
					resolve(tab);
				}
			});
		})(0);
	});
};

function tab_open(url) {
	return promisify(success => tab_open_(url, success), tab => tab);
}


const event_handlers = {
	all: async function(msg, resolve) {
		const all = (await get_all()).map(item_clean);
		resolve(all);
	},
	status: async function(msg, resolve) {
		const url = msg.url;
		console.log('status for ' + url);
		const matches = (await get_all()).map(item_clean).filter(by_url(url));
		resolve(matches);
	},
	activate: async function(msg, resolve) {
		const url = msg.url;
		console.log('active ' + url);
		let matches = (await get_tabs());
		// retain internal tab info, but make urls compatible
		matches = matches.map(item_clean_url).filter(by_url(url));
		if (!matches.length) {
			matches =	[await tab_open(url)];
		}
		const windowId = matches[0].windowId;
		W.update(windowId, {focused: true});
		T.highlight(tabs_highlight_compat({tabs: matches.map(item => item.index), populate: false, windowId: windowId}),
								_ => resolve(matches.map(item_clean)));
	},
	log: async function(msg, resolve) {
	},
	set: async function(msg, resolve) {
		const url = msg.url;
		const status = msg.status;
		const title = msg.title;

		const url_filter = by_url(url);
		const matching_tabs = (await get_tabs()).map(tab_clean).filter(url_filter);
		const matching_bookmarks = (await get_bookmarks()).map(bookmark_clean).filter(url_filter);
		if (status === TYPE_TAB) {
			if (!matching_tabs.length) {
				resolve([await tab_open(url)].map(tab_clean));
			}
			else {
				resolve(matching_tabs);
			}

			if (matching_bookmarks.length) {
				matching_bookmarks.map(bookmark => bookmark.id).forEach(id => B.remove(id));
			}
		}
		else if (status === TYPE_BOOKMARK) {
			if (!matching_bookmarks.length) {
				B.create(
					{title: title, url: url},
					bookmark => { resolve([bookmark_clean(bookmark)]); });
			}
			else {
				matching_bookmarks.forEach(b => B.update(b.id, { title: title }));
				resolve(matching_bookmarks);
			}

			if (matching_tabs.length) {
				T.remove(matching_tabs.map(tab => tab.id));
			}
		}
		else if (status === TYPE_KILL) {
			console.log('maybe kill tab for ', url);
			let ret = [];
			if (matching_tabs.length) {
				console.log('kill tab for ', url);
				T.remove(matching_tabs.map(tab => tab.id));
				ret = ret.concat(matching_tabs);
			}
			if (matching_bookmarks.length) {
				console.log('kill bookmark for ', url);
				matching_bookmarks.map(bookmark => bookmark.id).forEach(id => B.remove(id));
				ret = ret.concat(matching_bookmarks);
			}

			ret.forEach(item => item.type = TYPE_KILL)
			resolve(ret);
		}
		else {
			console.log('Unknown status: ' + status);
			assert(false);
		}

	},
};


// Interesting Events:
// chrome.webNavigation.onCompleted.addListener

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function connect() {
	let port = runtime.connectNative(NATIVE_HOST_NAME);
	console.log('connected');
	return port;
};


var port = connect();
port.onDisconnect.addListener(function() {
	console.log("Native Host Disconnected, reconnecting...");
	port = null;
	//setTimeout(function () { port = connect(); }, 1000);
});

runtime.onSuspend.addListener(function() {
    console.log("Unloading.");
    port.disconnect();
});

runtime.onInstalled.addListener(function() {
});


port.onMessage.addListener(async function(msg) {
	let imessage = msg.imessage;
	let payload = msg.payload;
	console.log("Received " + imessage + ' ' + payload.type);
	let resolve = response => {
		console.log('sending ' + imessage);
		console.log(response);
		port.postMessage({imessage: imessage, payload: response});
	};

	if (event_handlers.hasOwnProperty(payload.type)) {
		let handler = event_handlers[payload.type];
		handler(payload, resolve);
	}
	else {
		console.log('Unknown message:');
		console.log(msg);
		return;
	}

});


