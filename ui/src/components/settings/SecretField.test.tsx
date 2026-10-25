import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { useState } from 'react'
import { expectNoAxeViolations } from '../../test/axe'
import { SecretField } from './SecretField'
import type { SecretEdit, SecretState } from '../../lib/secrets'

function Harness({ state, onEdit }: { state: SecretState; onEdit?: (e: SecretEdit | undefined) => void }) {
  const [edit, setEdit] = useState<SecretEdit | undefined>()
  return (
    <SecretField
      label="App token"
      state={state}
      edit={edit}
      onEdit={(e) => { setEdit(e); onEdit?.(e) }}
    />
  )
}

describe('SecretField', () => {
  it('says a value is stored without showing it, and can replace it', async () => {
    const onEdit = vi.fn()
    const { container } = render(<Harness state="set" onEdit={onEdit} />)
    const input = screen.getByLabelText('App token')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('')
    expect(screen.getByText('Set')).toBeInTheDocument()
    expect(screen.getByText('A value is stored. It is never shown; type a new one to replace it.')).toBeInTheDocument()
    fireEvent.change(input, { target: { value: 'abc' } })
    expect(onEdit).toHaveBeenLastCalledWith({ kind: 'replace', value: 'abc' })
    expect(screen.getByText('Replaces the stored value when you save.')).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('asks for an unreadable value to be entered again', () => {
    render(<Harness state="unreadable" />)
    expect(screen.getByText('Cannot be read, re-enter it')).toBeInTheDocument()
    expect(screen.getByText(/cannot decrypt it with its current key/)).toBeInTheDocument()
  })

  it('removes a stored value only when asked, and Undo takes it back', () => {
    const onEdit = vi.fn()
    render(<Harness state="set" onEdit={onEdit} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove App token' }))
    expect(onEdit).toHaveBeenLastCalledWith({ kind: 'clear' })
    expect(screen.getByLabelText('App token')).toBeDisabled()
    expect(screen.getByText('Will be removed when you save.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Undo the change to App token' }))
    expect(onEdit).toHaveBeenLastCalledWith(undefined)
    expect(screen.getByLabelText('App token')).toBeEnabled()
  })

  it('offers no Remove when nothing is stored', () => {
    render(<Harness state="unset" />)
    expect(screen.getByText('Not set')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove/ })).not.toBeInTheDocument()
  })
})
