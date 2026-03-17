// SPDX-License-Identifier: AGPL-3.0-or-later

import Modal from './Modal'
import { Button } from './index'

interface ConfirmDialogProps {
  open: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: 'danger' | 'primary'
  loading?: boolean
}

export default function ConfirmDialog({
  open, onClose, onConfirm, title, message,
  confirmLabel = 'Confirm', cancelLabel = 'Cancel',
  variant = 'primary', loading = false,
}: ConfirmDialogProps) {
  return (
    <Modal open={open} onClose={onClose} title={title} size="sm">
      <p className="text-sm text-gray-300 mb-5">{message}</p>
      <div className="flex justify-end gap-3">
        <Button variant="secondary" size="sm" onClick={onClose} disabled={loading}>
          {cancelLabel}
        </Button>
        <Button
          variant={variant === 'danger' ? 'danger' : 'primary'}
          size="sm"
          onClick={() => { onConfirm(); onClose() }}
          disabled={loading}
        >
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  )
}
