<script lang="ts">
	async function devLogin() {
		const res = await fetch('/auth/dev/token', { credentials: 'include' });
		if (res.ok) {
			window.location.href = '/hierarchy';
		}
	}
</script>

<div class="login-container">
	<div class="login-card">
		<h1>Overslash</h1>
		<p>Sign in to manage your agents and identities.</p>

		<div class="login-buttons">
			<a href="/auth/google/login" class="btn btn-google">Sign in with Google</a>
			<button data-testid="dev-login" class="btn btn-dev" onclick={devLogin}>
				Dev Login
			</button>
		</div>
	</div>
</div>

<style>
	.login-container {
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 80vh;
	}

	.login-card {
		background: #fff;
		border-radius: 8px;
		padding: 40px;
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
		text-align: center;
		max-width: 400px;
		width: 100%;
	}

	.login-card h1 {
		margin: 0 0 8px;
		font-size: 24px;
	}

	.login-card p {
		color: #666;
		margin: 0 0 24px;
	}

	.login-buttons {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.btn {
		display: block;
		padding: 12px 20px;
		border-radius: 6px;
		font-size: 14px;
		font-weight: 500;
		text-decoration: none;
		cursor: pointer;
		border: none;
		text-align: center;
	}

	.btn-google {
		background: #4285f4;
		color: #fff;
	}

	.btn-google:hover {
		background: #3367d6;
	}

	.btn-dev {
		background: #e0e0e0;
		color: #333;
	}

	.btn-dev:hover {
		background: #ccc;
	}
</style>
