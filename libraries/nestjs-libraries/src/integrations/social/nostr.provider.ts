import {
  AuthTokenDetails,
  PostDetails,
  PostResponse,
  SocialProvider,
} from '@gitroom/nestjs-libraries/integrations/social/social.integrations.interface';
import { makeId } from '@gitroom/nestjs-libraries/services/make.is';
import dayjs from 'dayjs';
import { SocialAbstract } from '@gitroom/nestjs-libraries/integrations/social.abstract';
import { getPublicKey, nip19, Relay, finalizeEvent, SimplePool } from 'nostr-tools';

import WebSocket from 'ws';
import { AuthService } from '@gitroom/helpers/auth/auth.service';
import { Integration } from '@prisma/client';

// @ts-ignore
global.WebSocket = WebSocket;

const list = [
  'wss://nos.lol',
  'wss://relay.damus.io',
  'wss://relay.snort.social',
  'wss://temp.iris.to',
  'wss://vault.iris.to',
];

const pool = new SimplePool();

export class NostrProvider extends SocialAbstract implements SocialProvider {
  override maxConcurrentJob = 5;
  identifier = 'nostr';
  name = 'Nostr';
  isBetweenSteps = false;
  scopes = [] as string[];
  editor = 'normal' as const;
  toolTip = 'Paste your Nostr private key as a 64-character hex key or nsec1... value.'

  maxLength() {
    return 100000;
  }

  async customFields() {
    return [
      {
        key: 'password',
        label: 'Nostr private key',
        validation: `/^.{3,}$/`,
        type: 'password' as const,
      },
    ];
  }

  async refreshToken(refresh_token: string): Promise<AuthTokenDetails> {
    return {
      refreshToken: '',
      expiresIn: 0,
      accessToken: '',
      id: '',
      name: '',
      picture: '',
      username: '',
    };
  }

  async generateAuthUrl() {
    const state = makeId(17);
    return {
      url: state,
      codeVerifier: makeId(10),
      state,
    };
  }

  private secretKeyBytes(secret: unknown): Uint8Array {
    if (typeof secret !== 'string') {
      throw new Error('Nostr private key must be a 64-character hex key or nsec1... value');
    }

    const value = secret.trim();
    if (/^[0-9a-fA-F]{64}$/.test(value)) {
      return Uint8Array.from(value.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
    }

    if (value.startsWith('nsec1')) {
      try {
        const decoded = nip19.decode(value);
        if (decoded.type === 'nsec' && decoded.data instanceof Uint8Array) {
          return decoded.data;
        }
      } catch {
        // Fall through to the safe, format-only error below.
      }
    }

    throw new Error('Nostr private key must be a 64-character hex key or nsec1... value');
  }

  private async findRelayInformation(pubkey: string) {
    // This queries ALL relays in parallel and resolves with
    // the first matching event from ANY relay.
    const evt = await pool.get(list, {
      kinds: [0],
      authors: [pubkey],
      limit: 1,
    });

    if (!evt) return {};

    let content: any = {};
    try {
      content = JSON.parse(evt.content || '{}');
    } catch {
      return {};
    }

    if (content.name || content.displayName || content.display_name) {
      return content;
    }

    return {};
  }

  private async publish(_pubkey: string, event: any) {
    const accepted: string[] = [];
    const rejected: string[] = [];

    for (const relayUrl of list) {
      let relay: Relay | undefined;
      try {
        relay = await Relay.connect(relayUrl);
        await relay.publish(event);
        accepted.push(relayUrl);
      } catch (error) {
        const reason = String(error).replace(/\s+/g, ' ').slice(0, 160);
        rejected.push(`${relayUrl}: ${reason}`);
      } finally {
        relay?.close();
      }
    }

    console.info(
      `[social:nostr] event ${event.id} accepted by ${accepted.length}/${list.length} relays` +
        (rejected.length ? `; rejected: ${rejected.join(' | ')}` : '')
    );

    if (!accepted.length) {
      throw new Error(`Nostr rejected event ${event.id} on every configured relay`);
    }

    return event.id;
  }

  async authenticate(params: {
    code: string;
    codeVerifier: string;
    refresh?: string;
  }) {
    try {
      const body = JSON.parse(Buffer.from(params.code, 'base64').toString());

      const pubkey = getPublicKey(
        Uint8Array.from(
          body.password.match(/.{1,2}/g).map((byte: any) => parseInt(byte, 16))
        )
      );

      const user = await this.findRelayInformation(pubkey);

      return {
        id: pubkey,
        name: user.display_name || user.displayName || user.name || 'No Name',
        accessToken: AuthService.signJWT({ password: body.password }),
        refreshToken: '',
        expiresIn: dayjs().add(200, 'year').unix() - dayjs().unix(),
        picture: user?.picture || '',
        username: user.name || 'nousername',
      };
    } catch (e) {
      console.log(e);
      return 'Invalid credentials';
    }
  }

  private buildContent(post: PostDetails): string {
    const mediaContent = post.media?.map((m) => m.path).join('\n\n') || '';
    return mediaContent
      ? `${post.message}\n\n${mediaContent}`
      : post.message;
  }

  async post(
    id: string,
    accessToken: string,
    postDetails: PostDetails[]
  ): Promise<PostResponse[]> {
    const { password } = AuthService.verifyJWT(accessToken) as any;
    const [firstPost] = postDetails;

    const textEvent = finalizeEvent(
      {
        kind: 1, // Text note
        content: this.buildContent(firstPost),
        tags: [],
        created_at: Math.floor(Date.now() / 1000),
      },
      this.secretKeyBytes(password)
    );

    const eventId = await this.publish(id, textEvent);

    return [
      {
        id: firstPost.id,
        postId: String(eventId),
        releaseURL: `https://primal.net/e/${eventId}`,
        status: 'completed',
      },
    ];
  }

  async comment(
    id: string,
    postId: string,
    lastCommentId: string | undefined,
    accessToken: string,
    postDetails: PostDetails[],
    integration: Integration
  ): Promise<PostResponse[]> {
    const { password } = AuthService.verifyJWT(accessToken) as any;
    const [commentPost] = postDetails;
    const replyToId = lastCommentId || postId;

    const textEvent = finalizeEvent(
      {
        kind: 1, // Text note
        content: this.buildContent(commentPost),
        tags: [
          ['e', replyToId, '', 'reply'],
          ['p', id],
        ],
        created_at: Math.floor(Date.now() / 1000),
      },
      this.secretKeyBytes(password)
    );

    const eventId = await this.publish(id, textEvent);

    return [
      {
        id: commentPost.id,
        postId: String(eventId),
        releaseURL: `https://primal.net/e/${eventId}`,
        status: 'completed',
      },
    ];
  }
}
