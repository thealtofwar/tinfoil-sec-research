/**
 * Impact-lens verifier for candidate url-query-auto-submit-csrf.
 *
 * What a fresh chat started from /newchat?q= or /#send= actually carries,
 * i.e. the upper bound of what an attacker-chosen prompt can make the model
 * echo back: the base system prompt with the <user_preferences> block,
 * language and timezone substituted in. No chat history, no project
 * documents, no memory facts are present on a fresh chat.
 *
 * Also checks that the sign-in redirect strips the markers, so a victim who
 * is sent to sign-in first does NOT get the message auto-sent after login.
 */
import { useCustomSystemPrompt } from '@/components/chat/hooks/use-custom-system-prompt'
import {
  USER_PREFS_ADDITIONAL_CONTEXT,
  USER_PREFS_NICKNAME,
  USER_PREFS_PROFESSION,
  USER_PREFS_TRAITS,
} from '@/constants/storage-keys'
import { postAuthRedirectTarget, stripMessageMarkers } from '@/utils/redirect-url'
import { renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

const SERVER_PROMPT_SHAPE =
  'You are Tin, a helpful assistant.\n{USER_PREFERENCES}\nRespond in {LANGUAGE}. User timezone: {TIMEZONE}.'

describe('impact bound of a URL-auto-submitted prompt on a fresh chat', () => {
  it('system prompt carries the personalization profile + timezone and nothing else', async () => {
    localStorage.setItem(USER_PREFS_NICKNAME, 'Jane')
    localStorage.setItem(USER_PREFS_PROFESSION, 'oncology nurse')
    localStorage.setItem(USER_PREFS_TRAITS, JSON.stringify(['concise', 'skeptical']))
    localStorage.setItem(
      USER_PREFS_ADDITIONAL_CONTEXT,
      'I am being treated for HIV; keep answers private',
    )

    const { result } = renderHook(() => useCustomSystemPrompt(SERVER_PROMPT_SHAPE))
    await waitFor(() => expect(result.current.isUsingPersonalization).toBe(true))

    const prompt = result.current.effectiveSystemPrompt
    console.log('[impact] effective system prompt a fresh chat sends:\n' + prompt)

    expect(prompt).toContain('<user_preferences>')
    expect(prompt).toContain('<nickname>Jane</nickname>')
    expect(prompt).toContain('<profession>oncology nurse</profession>')
    expect(prompt).toContain('I am being treated for HIV')
    expect(prompt).toContain(Intl.DateTimeFormat().resolvedOptions().timeZone)
    // Nothing from other chats can be in here: the hook only reads the
    // personalization keys and the placeholders.
    expect(prompt).not.toMatch(/project_context|previous conversations/)
  })

  it('sign-in redirect strips ?q= and #send=, so a signed-out victim is not auto-sent after login', () => {
    const b64 = Buffer.from('leak me', 'utf8').toString('base64')
    expect(stripMessageMarkers(`/newchat?q=leak+me&x=1#send=${b64}`)).toBe('/newchat?x=1')
    expect(decodeURIComponent(postAuthRedirectTarget(`/?q=leak+me`))).toBe('/')
  })
})
