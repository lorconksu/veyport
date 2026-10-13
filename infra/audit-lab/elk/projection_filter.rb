# Second structural allowlist: HTTP metadata, headers and unexpected body fields
# cannot become search documents. No stdout/debug output exists in this pipeline.
def register(_params)
  @fields = %w[@timestamp schema_version redaction_rule_version event_id event_type record_sha256 actor_user_id actor_person_id actor_name execution_id node_id node_name run_as uid gid identity_sha256 policy_version policy_sha256 command_summary command_bytes command_sha256 script_bytes script_sha256 process_state evidence_state correlation_id request_id exit_code manifest_sha256 manifest_version_id retain_until]
  @types = %w[execution.admission execution.lifecycle execution.denial policy.intent policy.commit policy.result policy.anchor original_read.intent original_read.result]
end

def filter(event)
  path = event.get('[headers][request_path]')
  destination = event.sprintf('veyport-audit-%{+YYYY.MM.dd}')
  if path.is_a?(String) && path.start_with?('/replay/')
    candidate = path.delete_prefix('/replay/')
    return [] unless candidate.match?(/\Aveyport-replay-[a-z0-9_.-]{1,64}\z/)
    destination = candidate
  end
  return [] unless event.get('schema_version') == 1
  return [] unless event.get('redaction_rule_version') == 'structured-omit-arguments-v1'
  return [] unless @types.include?(event.get('event_type'))
  return [] unless event.get('event_id').is_a?(String) && event.get('event_id').match?(/\A[a-zA-Z0-9_.:-]{1,128}\z/)
  summary = event.get('command_summary')
  return [] unless summary.nil? || summary.match?(/\A(?:\[(?:multiline command redacted|command redacted)\]|(?:bash|sh|curl|wget|env|printf|echo|true|false|cat|ls|id|whoami|uname|date|sleep|sudo|systemctl|python3|node|git|docker|kubectl) \[arguments redacted\])\z/)
  event.to_hash.keys.each { |key| event.remove(key) unless @fields.include?(key) }
  event.set('[@metadata][destination_index]', destination)
  [event]
end
